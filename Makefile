################################################################################
#
# MKA daemon
# SPDX-FileCopyrightText: 2022 Technica Engineering GmbH <macsec@technica-engineering.de>
# SPDX-License-Identifier: GPL-2.0-or-later
# file: Makefile
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
# waf build system wrapper
WAF=python3 waf

all:
	${WAF} build

build:
	${WAF} build

install:
	${WAF} install

uninstall:
	${WAF} uninstall

test:
	${WAF} test

help:
	${WAF} --help

clean:
	${WAF} clean

distclean:
	${WAF} distclean

# Pending
dist:
	${WAF} dist

distcheck:
	${WAF} distcheck

.PHONY: build test
