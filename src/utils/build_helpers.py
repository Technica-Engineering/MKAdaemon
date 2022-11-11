#encoding: utf-8
#vim syntax=python fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4
#
################################################################################
#
# MKA daemon.
# SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
# SPDX-License-Identifier: GPL-2.0-or-later
# file: build_helpers.py
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
# Waf build system script
#

from waflib import TaskGen, Configure, Node, Build, Utils, Scripting, Logs
import os, subprocess

def build(bld):
    bld.compile_standalone = bool(getattr(bld, 'project', None) is None)

def distclean(ctx):
    Scripting.distclean(ctx)

@TaskGen.taskgen_method
def add_include(ctx, inc):
    ctx.env.INCLUDES.append(ctx.bld.get_dir(inc).abspath())

@TaskGen.taskgen_method
def add_source(ctx, src, **kw):
    task = {
        'c' : 'c',
        'cpp' : 'cxx',
    }[
        src.rsplit('.')[-1]
    ]

    ctx.create_compiled_task(task, ctx.bld.get_file(src))

@TaskGen.after_method('__init__')
def initialise(ctx):
    print(ctx)

@Configure.conf
def nodify(bld, target):
    if not isinstance(target, Node.Node):
        target = bld.path.find_resource(target) or bld.path.find_or_declare(target)
    return target

@Configure.conf
def get_dir(bld, folder):
    loc = bld.path.find_dir(folder)
    if not loc:
        print(' ERROR: Cannot find folder %s.' % folder)
        sys.exit(1)
    return loc

@Configure.conf
def get_file(bld, folder):
    loc = bld.nodify(folder)
    if not loc:
        print(' ERROR: Cannot find file %s.' % filename)
        sys.exit(1)
    return loc

@Configure.conf
def splitter(conf, values):
    if type(values) is list:
        for elem in values:
            yield elem
    elif type(values) is str:
        for elem in values.split():
            yield elem
    else:
        assert False, "Unhandled type %s" % type(values)

@Configure.conf
def check_headers(conf, headers, errmsg="no"):
    for header in conf.splitter(headers):
        conf.check(
            fragment='#include <%s>\nint main() { return 0; }\n' % header,
            features='c',
            type='nolink',
            msg='Checking for header %s' % header,
            errmsg=errmsg,
        )

@Configure.conf
def check_libraries(conf, libraries, errmsg="no"):
    for library in conf.splitter(libraries):
        conf.check(
            fragment='int main() { return 0; }\n',
            features='c cprogram',
            lib=library,
            msg='Checking for library %s' % library,
            errmsg=errmsg,
        )

@Configure.conf
def shell_cmd(conf, command, on_error=None, **kw):
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    stdout, stderr = p.communicate()
    stdout, stderr = stdout.decode("utf-8"), stderr.decode("utf-8")
    retcode = p.wait()

    if on_error is not None and 0 != retcode:
        return on_error, on_error

    assert 0 == retcode, ("FATAL while executing [%s]\r\n"%command)+stdout+stderr
    return stdout, stderr

@Configure.conf
def get_git_version(conf):
    if 'GIT' not in conf.env:
        if not conf.find_program("git", var="GIT", mandatory=False):
            Logs.pprint('CYAN', '  > WARNING! No GIT tool installed, cannot get software version. Using "unknown".')
            conf.env.GIT = None

    if conf.env.GIT:
        return conf.shell_cmd(conf.env.GIT + ["describe", "HEAD"], on_error="UNKNOWN")[0].rstrip("\r\n")
    else:
        return "UNKNOWN"
    
