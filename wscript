#encoding: utf-8
#vim syntax=python fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4
#
################################################################################
#
# MKA daemon.
# SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
# SPDX-License-Identifier: GPL-2.0-or-later
# file: wscript
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
################################################################################

from __future__ import print_function
from waflib import Configure, Utils, Logs, Build
from collections import defaultdict
import sys, os, subprocess

# WAF configuration: Top directory and build directory, auto config
top, out, Configure.autoconfig = '.', 'build', True

# Component inclusion
@Configure.conf
def build_as_component(bld):
    bld.project.add_include('src')

    # Crypto code ---------------------------------
    bld.project.add_include('src/crypto')
    bld.project.add_source('src/crypto/aes-kdf.c')
    bld.project.add_source('src/crypto/aes-omac1.c', lint=False)

    if bld.project.options.get('crypto_openssl', None):
        bld.project.add_source('src/crypto/mka_crypto_openssl.c')

    else:
        bld.fatal('MKA compilation aborted, no crypto stack selected!')

    # Utilities ----------------------------------
    bld.project.add_include('src/utils')
    bld.project.add_source('src/utils/mka_logging.c')

    # Layer 2 communication ----------------------
    bld.project.add_include('src/l2')

    if bld.project.options.get('l2_linux', None):
        bld.project.add_source('src/l2/mka_l2_linux.c')

    else:
        bld.fatal('MKA compilation aborted, no layer 2 access selected!')

    # MKA core -----------------------------------
    bld.project.add_include('src/pae')
    bld.project.add_source('src/pae/mka_cp.c')
    bld.project.add_source('src/pae/mka_kay.c')
    bld.project.add_source('src/pae/mka_kay_params.c')
    bld.project.add_source('src/pae/mka_logon.c')
    bld.project.add_source('src/pae/mka_secy.c')
    bld.project.add_source('src/mka_main.c')

# -------- Standalone compilation ----------
def build(bld):
    bld.compile_standalone = bool(getattr(bld, 'project', None) is None)
    # As standalone daemon
    if bld.compile_standalone:
        bld.env.DEFINES += bld.env.DEFINES_STANDALONE
        dbus_src = ''
        if 'ENABLE_DBUS' in bld.env.DEFINES:
            Logs.pprint('CYAN', 'Compiling with DBUS API Support')
            bld(
                source = 'src/linux_daemon/gdbus-mkad.xml',
                target = 'src/linux_daemon/gdbus-mkad-generated.c src/linux_daemon/gdbus-mkad-generated.h src/linux_daemon/mkad-dbus-docs-de.technica_engineering.mkad.BUS.xml',
                rule = '${GDBUS_CODEGEN} --interface-prefix de.technica_engineering.mkad. --output-directory src/linux_daemon --generate-c-code gdbus-mkad-generated --c-namespace mkad --c-generate-object-manager --generate-docbook mkad-dbus-docs ${SRC}'
            )
            bld.add_group()
            dbus_src = 'src/linux_daemon/gdbus-mkad-generated.c src/linux_daemon/dbus_server.c'
            bld.program(
                source = 'src/mkad_cli/main.c src/linux_daemon/gdbus-mkad-generated.c',
                includes = 'src/linux_daemon',
                target = 'mkad_cli',
            )
        else:
            Logs.pprint('CYAN', 'DBUS API Support has been disabled')

        bld.load('build_helpers', tooldir='src/utils')
        bld.project = bld.program(
            source = 'src/linux_daemon/main.c src/linux_daemon/mka_daemon_config.c src/linux_daemon/mka_timers_event.c '+
                     'src/linux_daemon/mka_phy_driver_libnl.c src/linux_daemon/mka_link_monitor.c ' + dbus_src,
            includes = 'src/linux_daemon',
            target = 'mkad',
            features = 'c cprogram',
        )

        bld.project.options = defaultdict(None)
        bld.project.options['crypto_openssl'] = True
        bld.project.options['l2_linux'] = True

        if 'MKA_ALLOW_OTHER_VERSIONS' in os.environ:
            bld.env.DEFINES += ["MKA_ALLOW_OTHER_VERSIONS=1"]

        if 'CONFIG_MACSEC_HW_OFFLOAD' not in bld.env.DEFINES:
            Logs.pprint('CYAN', 'WARNING: This compilation has disabled MACsec HW offloading.')

        if 'CONFIG_MACSEC_XPN_SUPPORT' not in bld.env.DEFINES:
            Logs.pprint('CYAN', 'WARNING: This compilation has disabled MACsec XPN cipher suites.')
        
        if False == os.environ.get('DEBUG', False):
            bld.add_post_fun(lambda bld: os.system("strip build/mkad build/mkad_cli >/dev/null 2>/dev/null"))

    # As SW Component
    return build_as_component(bld)

def configure(conf):
    conf.load('build_helpers', tooldir='src/utils')

    # Load C compiler with native dependency tracking (gccdeps)
    conf.load('compiler_c compiler_cxx gnu_dirs gccdeps')

    # Choose if the Dbus API is disabled
    if not int(os.getenv('DISABLE_DBUS', False)):
        conf.env.DEFINES_STANDALONE += [
            "ENABLE_DBUS",
        ]

    # Validate necessary tools
    if "ENABLE_DBUS" in conf.env.DEFINES_STANDALONE:
        conf.find_program(["gdbus-codegen"], var="GDBUS_CODEGEN")

    # Force definition of some variables
    for var in [ 'CFLAGS', 'CXXFLAGS', 'ASFLAGS', 'DEFINES', 'INCLUDES', 'LINKFLAGS', 'LDFLAGS', 'LIB', 'LIBPATH']:
        conf.env[var] = conf.env[var] + os.environ.get(var, '').split()

    # Validate necessary linux socket libraries available
    conf.check_headers("stdio.h sys/types.h sys/socket.h errno.h net/if.h linux/if_packet.h sys/ioctl.h unistd.h")

    # Validate Posix Threads available
    conf.check_headers("pthread.h")
    conf.check_libraries("pthread")

    # Validate packages available
    conf.check_cfg(package="libcrypto", args="--libs --cflags", errmsg="no, please install openssl")
    conf.check_cfg(package="yaml-0.1", args="--libs --cflags", errmsg="no, please install libyaml-dev")
    conf.check_cfg(package="libbsd", args="--libs --cflags", errmsg="no, please install libbsd-dev")
    conf.check_cfg(package="libnl-3.0", args="--libs --cflags", errmsg="no, please install libnl-3-dev")
    conf.check_cfg(package="libnl-genl-3.0", args="--libs --cflags", errmsg="no, please install libnl-genl-3-dev")
    conf.check_cfg(package="libnl-route-3.0", args="--libs --cflags", errmsg="no, please install libnl-route-3-dev")
    if "ENABLE_DBUS" in conf.env.DEFINES_STANDALONE:
        conf.check_cfg(package="gio-2.0", args="--libs --cflags", errmsg="no, please install libglib2.0-dev")
        conf.check_cfg(package="gio-unix-2.0", args="--cflags", errmsg="no, please install libglib2.0-dev")
        conf.check_cfg(package="libxml-2.0", args="--libs --cflags", errmsg="no, please install libxml2-dev")

    # Validate Libnetlink available
    conf.check_cfg(package="libnl-3.0")
    #conf.check_headers("libnl3/netlink/netlink.h", "no, please install libnl-3-dev")
    conf.check_libraries("nl-3", "no, please install libnl-3-dev")

    # Project parameters
    conf.env.CFLAGS = ( # Attempt to catch errors as soon as possible
            "-Wall -Wextra -Wunused -Werror -Wstrict-overflow -Wshadow -Wstack-usage=1536 "
            " -Wpointer-arith -Wundef -Wno-c99-c11-compat "
            " -Wcast-align -Wmissing-prototypes -Wwrite-strings  "
            " -Wno-unused-parameter -Wno-variadic-macros -Wno-type-limits -O2 -Wno-deprecated-declarations"
        ).split() + conf.env.CFLAGS
    conf.env.LDFLAGS = '-delete'.split() + conf.env.LDFLAGS

    # Debug compilation
    if os.environ.get('DEBUG', False):
        conf.env.CFLAGS += ["-Og", "-ggdb", "-fsanitize=address", "-fsanitize=undefined"]
        conf.env.LINKFLAGS += ["-fsanitize=address", "-fsanitize=undefined"]

    conf.env.DEFINES_STANDALONE += [
        "MKA_STANDALONE_COMPILATION",
        "DAEMON_VERSION=\"%s\"" % conf.get_git_version(),
    ]

    # Automatically use in our compilation all checked libraries, library path's, and include paths
    conf.env['LIB'] += { l for x in conf.env if (x.startswith('LIB_') and x != 'LIB_ST') for l in conf.env[x] }
    conf.env['LIBPATH'] += { p for x in conf.env if (x.startswith('LIBPATH_') and x != 'LIBPATH_ST') for p in conf.env[x] }
    conf.env['INCLUDES'] += { d for x in conf.env if x.startswith('INCLUDES_') for d in conf.env[x] }

    # Checking MACsec offload capability in library
    has_offloading = conf.check(
        fragment='#include <netlink/route/link/macsec.h>\n int main() { (void)rtnl_link_macsec_set_offload; }\n',
        features='c cprogram',
        msg='Checking for MACsec offloading',
        mandatory=False,
    )
    if has_offloading:
        conf.env.DEFINES_STANDALONE += [
            "CONFIG_MACSEC_HW_OFFLOAD",
        ]

    # Checking kernel support for XPN
    has_xpn = conf.check(
        fragment='#include <linux/if_macsec.h>\n int main() { (void)MACSEC_SA_ATTR_SSCI; }\n',
        features='c cprogram',
        msg='Checking linux kernel support for XPN',
        mandatory=False,
    )
    if has_xpn:
        conf.env.DEFINES_STANDALONE += [
            "CONFIG_MACSEC_XPN_SUPPORT",
        ]

    # Load google test tool
    conf.load('googletest', tooldir='thirdparty')
    if conf.env.GTEST_INCLUDE:
        conf.recurse('test')

def test(tst):
    tst.recurse('test')

def options(opts):
    opts.load('build_helpers', tooldir='src/utils')
    opts.load('compiler_c compiler_cxx gnu_dirs')
    opts.load('googletest', tooldir='thirdparty')
    opts.recurse('test')

def distclean(opts):
    opts.load('build_helpers', tooldir='src/utils')
    opts.load('googletest', tooldir='thirdparty')

def dist(ctx):
    ret, out, err = Utils.run_process("git describe --tags HEAD".split(), {'stdout':subprocess.PIPE})
    ctx.arch_name = 'mkad-' + out.split()[0].decode('utf-8') + '.tar.bz2'
    ctx.base_name = 'files'
    with open('.gitignore') as f:
        ctx.excl = f.read()

distcheck = dist

