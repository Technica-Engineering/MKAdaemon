#encoding: utf-8
#vim syntax=python fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4
#
################################################################################
#
# MKA daemon.
# SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
# SPDX-License-Identifier: GPL-2.0-or-later
# file: googletest.py
#
# © 2022 Technica Engineering GmbH.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see https://www.gnu.org/licenses/
#
################################################################################
#
# WAF targets for UT compilation and execution with code coverage using Google Test.
#
# Author:   Andreu Montiel
# Date:     09/11/2022
#

import os, re, subprocess, shutil, glob
from waflib import Configure, Build, Logs
from waflib.TaskGen import feature, after_method, before_method, task_gen
from waflib.Utils import to_list
from waflib.Node import Node
from collections import OrderedDict

GTEST_PATH="thirdparty/googletest"

EXTRA_CFLAGS = [
    '--coverage', '-g', '-ggdb', '-O0', '-fprofile-arcs', '-ftest-coverage', '-fno-inline', 
    '-fno-inline-functions', #'-fkeep-inline-functions',
]
EXTRA_LINKFLAGS = [
    '--coverage', '-g', '-ggdb', '-O0', '-fprofile-arcs', '-ftest-coverage', '-fno-inline', 
    '-fno-inline-functions', #'-fkeep-inline-functions',
]

EXTRA_USE_UT = to_list("GTEST GTEST_MAIN GMOCK RT PTHREAD")

class BuildUT(Build.BuildContext):
    """ Waf compilation target for unit tests.
    """
    cmd = 'test'
    fun = 'test'
    tests = list()
    coverage_enable = False

    @staticmethod
    def remove_dups(elements):
        return list(OrderedDict([(element, 1) for element in elements]).keys())

    def add(self, *k, **kw):
        """ Add a unit test.
        """
        if not self.env.GTEST_INCLUDE:
            self.fatal("Unit tests disabled. Please fulfill dependencies and re-run configure.")
        self.__class__.coverage_enable = (self.options.coverage.lower() == 'yes') and self.env.LCOV and self.env.GCOV

        kw['features'] = to_list(kw.get('features','')) + to_list("cxxprogram c cxx selective_coverage")
        assert 'name' in kw, "Name is mandatory in a unit test"
        assert re.match('^[\w\d_]+$', kw['name']), "Invalid name. It's restricted to letters, numbers and _"
        test_name = kw['name']

        kw['name']      = test_name
        kw['target']    = test_name
        kw['cflags']    = self.remove_dups(to_list(kw.get('cflags',''))   + EXTRA_CFLAGS)
        kw['cxxflags']  = self.remove_dups(to_list(kw.get('cxxflags','')) + EXTRA_CFLAGS)
        kw['linkflags'] = self.remove_dups(to_list(kw.get('cxxflags','')) + EXTRA_LINKFLAGS)
        kw['use']       = self.remove_dups(EXTRA_USE_UT + to_list(kw.get('use','')))
        kw['includes']  = self.remove_dups(self.env.GTEST_INCLUDE + to_list(kw.get('includes','')))

        no_coverage = to_list(kw['coverage_disable'])
        kw['selective_coverage_exclude'] = [self.path.find_node(x) if not issubclass(type(x), Node) else x for x in no_coverage]
        missing = [no_coverage[i] for i, node in enumerate(kw['selective_coverage_exclude']) if node is None]
        if any(missing):
            self.fatal("Attribute [coverage_disable] of test [%s]: Cannot find files or folders with name [%s]" % (test_name, ','.join(missing)))
        kw['selective_coverage_flags'] = ["--coverage", "-ftest-coverage", "-fprofile-arcs"]

        self.launch_opts = (["--gtest_filter=%s" % self.options.gtest_filter] if self.options.gtest_filter else [])
        self.launch_opts += to_list(self.options.launchopt or []) + to_list(kw.get('launchopts', []))

        self.tests.append(test_name)
        
        taskgen_test_compilation = Build.BuildContext.__call__(self, *k, **kw)
        # forcefully provide unique identifier to objects of each test. waf mechanism is broken?
        taskgen_test_compilation.idx = 1000 + len(self.tests)

    def __call__(self, *k, **kw):
        """ Implement the call operator, so behavior is more waf-like..
        """
        return self.add(*k, **kw)

    def execute(self):
        """ Execute build. Build is modified here to run the tests after compilation.
        """
        result = Build.BuildContext.execute(self)
        any_test = False
        test_results = 0
        failed = list()

        # Search unit tests executables after compilation
        for group in self.groups:
            for generator in group:
                for task in generator.tasks:
                    if (generator.name in self.tests) and task.outputs and \
                            task.outputs[0].name == generator.name:
                        # Execute it
                        result = self.runner(generator.name, task.outputs[0], task.inputs)
                        if 0 != result:
                            failed.append(generator.name)
                        if self.coverage_enable:
                            self.partial_coverage(generator.name, task.inputs)
                        any_test = True

        if self.coverage_enable and any_test and len(self.tests) > 1:
            self.merge_coverages()

        if failed:
            text = "  You can run them individually via:\r\n"
            for test in failed:
                text += "    $ python waf test --targets=%s --gtest_filter=*\r\n" % test
            text += "\r\n"
            text += "  Optionally restrict execution to specific tests via --gtest_filter=*suite*or*test*\r\n"
            self.fatal('\nERROR: One or more unit tests have failed.\r\n'+text)

        return result

    def merge_coverages(self):
        """ Merge coverages of several unit tests into a global coverage metric.
            An HTML report is also generated to help visualise covered code.
        """
        cwd = self.path.get_bld().abspath()

        partial_coverages = []
        for root, dirs, files in os.walk(cwd, topdown=False):
            for name in files:
                filepath = os.path.join(root,name)
                if name == 'lcov_coverage.info' and os.path.getsize(filepath) > 0:
                    partial_coverages.append(filepath)

        self.exec_command('rm -f lcov_coverage_global.info', cwd=cwd)

        if partial_coverages:
            params = ['-a', 'xx'] * len(partial_coverages)  # -a file0 -a file1 -a file2 ...
            params[1::2] = partial_coverages                # put file0, file1, file2...

            lcov_merge_execution = self.subprocess_run(
                self.env.LCOV + params + ['-o', 'lcov_coverage_global.info'],
                capture_output=True, 
                cwd = cwd,
            )

        if not partial_coverages or (lcov_merge_execution.returncode != 0):
            if not partial_coverages or ('no valid records found' in lcov_merge_execution.stderr.decode("utf-8")):
                print('  -> No global coverage information')
                print('')
                return

            print(lcov_merge_execution.stdout)
            print(lcov_merge_execution.stderr)
            self.fatal('LCOV execution failed [%i]: cannot join partial code coverages' % lcov_merge_execution.returncode)

        lcov_output = (lcov_merge_execution.stdout+lcov_merge_execution.stderr).decode("utf-8")
        for summary in re.findall('Summary.*', lcov_output, re.MULTILINE|re.DOTALL):
            print('Global s'+summary[1:])

        # Generate html report
        self.exec_command('genhtml -o global_coverage_report lcov_coverage_global.info >/dev/null', cwd=cwd)

        print('  -> HTML report in %s/global_coverage_report' % self.path.get_bld().path_from(self.path.get_src()))
        print('')

    def runner(self, test_name, executable, objects):
        """ Handle Ut execution.
        """
        cwd = self.path.get_bld().abspath()
        result_folder = self.path.get_bld().find_node('result_'+test_name) or \
                self.path.get_bld().make_node('result_'+test_name)

        result_folder.mkdir()

        result_xml = result_folder.find_or_declare(test_name+'.xml')

        for obj in objects:
            # Remove coverage data of previous executions
            self.exec_command('rm -f ' + obj.abspath()[:-2] + '.gcda', cwd=cwd)

        launch_cmd = [
            executable.abspath(),
            '--gtest_color=yes',
            '--gtest_output=xml:%s' % result_xml.abspath(),
        ] + self.launch_opts

        result = self.subprocess_run(
            launch_cmd,
            cwd=cwd,
        )
        print('')

        return result.returncode

    @staticmethod
    def subprocess_run(cmd, **kw):
        """ Implementation wrapper compatible with python2, python3.6 and python3.7 """

        if 'capture_output' in kw:
            kw.pop('capture_output')
            kw['stdout'] = subprocess.PIPE
            kw['stdin'] = subprocess.PIPE

        class result(object):
            def __init__(self, **kw):
                self.__dict__.update(kw)

        p = subprocess.Popen(cmd, **kw)
        stdout, stderr = p.communicate()
        stdout, stderr = stdout or b'', stderr or b''
        retcode = p.wait()

        return result(returncode=retcode, stdout=stdout, stderr=stderr)

    def partial_coverage(self, test_name, objects):
        """ Handle partial coverages of UT's and join them into a global metric.
        """
        cwd = self.path.get_bld().abspath()
        result_folder = self.path.get_bld().find_node('result_'+test_name)
        cov_folder = result_folder.find_node('gcxx') or result_folder.make_node('gcxx')
        cov_folder.mkdir()
        lcov_file = result_folder.find_or_declare('lcov_coverage.info')

        self.exec_command('rm -f ' + lcov_file.abspath(), cwd=cwd)

        for obj in objects:
            # Copy coverage files to result folder
            for cov_file in glob.glob(obj.abspath()[:-2] + '.gc*'):
                self.exec_command('cp ' + cov_file + ' ' + cov_folder.abspath(), cwd=cwd)

        # Generate a report with lcov
        self.exec_command(' '.join(self.env.LCOV)+' --capture --directory %s --output-file %s >/dev/null 2>&1' % (
                cov_folder.abspath(),
                lcov_file.abspath(),
            ),
            cwd=cwd
        )

        # Exclude system headers from report
        for remove_pattern in ["/usr/*", "*%s*" % GTEST_PATH, "*mocks*", "*test*"]:
            self.exec_command(' '.join(self.env.LCOV)+' --remove %s "%s" --output-file %s >/dev/null 2>&1' % (
                    lcov_file.abspath(),
                    remove_pattern,
                    lcov_file.abspath(),
                ),
                cwd=cwd
            )

        if os.path.getsize(lcov_file.abspath()) > 0:
            # Print summary
            lcov_info = self.subprocess_run(
                self.env.LCOV + ['-a', lcov_file.abspath()],
                capture_output=True,
                cwd=cwd,
            )
        else:
            lcov_info = None

        if lcov_info is None or lcov_info.returncode != 0:
            if lcov_info is None or 'no valid records found' in lcov_info.stderr.decode("utf-8"):
                print('  -> No partial coverage information')
                print('')
                return

            print(lcov_info.stdout)
            print(lcov_info.stderr)
            self.fatal('LCOV execution failed [%i]: cannot get a summary of code coverage' % lcov_info.returncode)

        lcov_output = (lcov_info.stdout+lcov_info.stderr).decode("utf-8")
        for summary in re.findall('Summary.*', lcov_output, re.MULTILINE|re.DOTALL):
            if len(self.tests) > 1: # Multiple tests. Modify output so that GitLab regex doesn't catch it.
                print('Test [%s] partial s%s' % (test_name, summary[1:].replace('\n  ', '\n |-')))
            else:
                print(summary)

        # Generate html report
        self.exec_command('genhtml -o %s/coverage_report %s >/dev/null' % (
                result_folder.abspath(),
                lcov_file.abspath(),
            ),
            cwd=cwd
        )

        print('  -> HTML report in %s/coverage_report' % result_folder.path_from(self.path.get_src()))
        print('')

class CleanUT(Build.CleanContext):
    cmd = 'clean_test'
    fun = 'test'

# This is a selective coverage waf feature, basically:
#  - It allows to define a set of "selective coverage flags".
#  - It allows to define a set of included source files, or a set of excluded set files
#
#  - If a set of included source files is given:
#    -> This feature will add the given flags to the source files contained inclusion list.
#    -> This feature will remove the given flags to the rest of source files.
#
#  - If on the other hand a set of excluded source files is given:
#    -> This feature will remove the given flags to the source files contained in the excluded list.
#    -> This feature will add the given flags to the the rest of source files.
#
@feature('selective_coverage')
@after_method('process_source')
def selective_coverage_process_source(tskgen):
    include = getattr(tskgen, 'selective_coverage_include', [])
    exclude = getattr(tskgen, 'selective_coverage_exclude', [])
    flags = getattr(tskgen, 'selective_coverage_flags', [])
    matcher = getattr(tskgen, 'selective_coverage_flag_matcher', lambda f: False)
    
    if (not include and not exclude) or (not flags):
        return

    if include:     is_covered = lambda node: node in include or any(node.is_child_of(p) for p in include)
    else:           is_covered = lambda node: node not in exclude and not any(node.is_child_of(p) for p in exclude)

    filter_func = lambda f: not (matcher(f) or (f in flags))

    exclude_flag_filter = lambda flag_list: list(filter(filter_func, to_list(flag_list)))
    include_flag_filter = lambda flag_list: exclude_flag_filter(flag_list) + flag_list

    # Get compilation tasks (.c -> .o jobs)
    for tsk in tskgen.compiled_tasks:
        if is_covered(tsk.inputs[0]):
            tsk.env.CFLAGS = include_flag_filter(tsk.env.CFLAGS)
            tsk.env.CXXFLAGS = include_flag_filter(tsk.env.CXXFLAGS)

        else:
            tsk.env.CFLAGS = exclude_flag_filter(tsk.env.CFLAGS)
            tsk.env.CXXFLAGS = exclude_flag_filter(tsk.env.CXXFLAGS)

def options(opts):
    opts.add_option('--launchopt', action='store', default=None, help="Google Test launch options")
    opts.add_option('--gtest_filter', action='store', default=None, help="Google Test run filter")
    opts.add_option('--coverage', action='store', default='yes', help='Enables/disables code coverage of unit tests')

@Configure.conf
def prepare_gtest(conf):
    def compile_gtest(conf):
        try:
            result = conf.cmd_and_log("cd %s && (rm -f CMakeCache.txt || true) && cmake . && make -j 5 && " \
                "(rm -rf googletest/generated || true)" % GTEST_PATH)
        except:
            conf.fatal("Could not compile GoogleTest")

        return result

    r = conf.test(build_fun=compile_gtest,
            cwd="thirdparty/googletest",
            msg="Precompiling GTest library",
            okmsg="ok",
            errmsg="error",
        )

    conf.env.STLIBPATH += [os.getcwd() + '/' + GTEST_PATH + '/lib']

def configure(conf):
    deps = list()
    deps.append(conf.find_program(["cmake"], var="CMAKE", mandatory=False, errmsg="no, unit tests disabled."))
    deps.append(conf.find_program(["make"], var="MAKE", mandatory=False, errmsg="no, unit tests disabled."))
    deps.append(conf.check(lib='rt', uselib_store='RT', mandatory=False, errmsg="no, unit tests disabled."))
    deps.append(conf.check(lib='pthread', uselib_store='PTHREAD', mandatory=False, errmsg="no, unit tests disabled."))

    conf.find_program('gcov', var='GCOV', mandatory=False, errmsg="no, unit test coverage disabled.")
    conf.find_program('lcov', var='LCOV', mandatory=False, errmsg="no, unit test coverage disabled.")

    conf.start_msg('Checking for GoogleTest submodule')
    has_gtest = os.path.exists(GTEST_PATH+'/CMakeLists.txt')
    conf.end_msg('yes' if has_gtest else 'no, please download submodules to run UTs', 'GREEN' if has_gtest else 'RED')
    deps.append(has_gtest)

    if all(deps):
        conf.prepare_gtest()

        conf.check(lib='gtest', uselib_store='GTEST')
        conf.check(lib='gtest_main', uselib_store='GTEST_MAIN')
        conf.check(lib='gmock', uselib_store='GMOCK')

        conf.env.GTEST_INCLUDE = [
            os.getcwd() + '/' + GTEST_PATH + '/googletest/include',
            os.getcwd() + '/' + GTEST_PATH + '/googlemock/include',
        ]

        conf.check(
                lib='gtest gtest_main gmock pthread', features='cxx cxxprogram', includes=conf.env.GTEST_INCLUDE,
                msg='Checking Google Test environment works',
                fragment='#include "gtest/gtest.h"\n'+'#include "gmock/gmock.h"\n'+'TEST(dummy, example) { ASSERT_THAT(1, ::testing::Ge(1)); }\n'
            )

    if not all(deps):
        Logs.pprint('YELLOW', "Warning: Dependencies for unit testing not satisfied. UT's disabled.")

    elif not conf.env.GCOV or not conf.env.LCOV:
        Logs.pprint('YELLOW', "Warning: Dependencies for unit test coverage not satisfied. UT coverage disabled.")
        

def test(tst):
    pass
