#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
# mk1onepass, Generate one time password for multi purpose.
# Copyright (C) 2024 Mike Turkey All rights reserved.
# contact: voice[ATmark]miketurkey.com
# license: GPLv3 License
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# ADDITIONAL MACHINE LEARNING PROHIBITION CLAUSE
#
# In addition to the rights granted under the applicable license(GPL-3),
# you are expressly prohibited from using any form of machine learning,
# artificial intelligence, or similar technologies to analyze, process,
# or extract information from this software, or to create derivative
# works based on this software.
#
# This prohibition includes, but is not limited to, training machine
# learning models, neural networks, or any other automated systems using
# the code or output of this software.
#
# The purpose of this prohibition is to protect the integrity and
# intended use of this software. If you wish to use this software for
# machine learning or similar purposes, you must seek explicit written
# permission from the copyright holder.
#
# see also 
#     GPL-3 Licence: https://www.gnu.org/licenses/gpl-3.0.html.en
#     Mike Turkey.com: https://miketurkey.com/

import os
import fnmatch
import pprint
import time
import re
import sys
import shlex
import _io
import shutil
import stat
import string
import inspect
import argparse
import tomllib
import copy
import types
import subprocess


class _Vcheck(object):
    @staticmethod
    def fname(s: str, vname: str = ''):
        maxbyte: int = 255
        if isinstance(s, str) != True:
            errmes = 'Error: {0} is not string.'.format(vname)
            r = False if vname == '' else errmes
            return r
        if len(s.encode('UTF-8')) > maxbyte:
            errmes = 'Error: {0} is {1} byte over. [{2}]'.format(
                vname, maxbyte, s)
            r = False if vname == '' else errmes
            return r
        r = True if vname == '' else ''
        return r


class Vcheck(object):
    @staticmethod
    def fname(fname: str, vname: str) -> str:
        func = _Vcheck.fname
        errmes = func(fname, vname)
        if errmes != '':
            print(errmes, file=sys.stderr)
            exit(1)
        return


class Mainfunc(object):
    @staticmethod
    def findcmd_byPATH(cmd: str) -> str:
        vcheck = Vcheck
        vcheck.fname(cmd, 'cmd')
        pathenv_str = os.getenv('PATH')
        pathenv_lst = pathenv_str.split(':')
        for pathenv_dir in pathenv_lst:
            if not os.path.isdir(pathenv_dir):
                continue
            fpath_cmd = os.path.join(pathenv_dir, cmd)
            if os.access(fpath_cmd, os.X_OK):
                return fpath_cmd
        return ''

    @staticmethod
    def load_config(fpath: str) -> dict:
        if os.path.isfile(fpath) != True:
            errmes = 'Error: Not found config. [{0}]'.format(fpath)
            print(errmes, file=sys.stderr)
            exit(1)
        with open(fpath, 'rt')as fp:
            templist = [s for s in fp]
        s = ''.join(templist)
        d = tomllib.loads(s)
        conf = types.SimpleNamespace(gpgkeyid='')
        k = 'GPGKEYID'
        if k in d.keys():
            conf.gpgkeyid = d[k]
        return copy.copy(conf)

    @staticmethod
    def mk_secdict(rows: list) -> dict:
        secdict = dict()
        secdict_v_empty = types.SimpleNamespace(secretkey='', ercode=[])
        if isinstance(rows, list) != True:
            errmes = 'Error: rows is not list.'
            raise TypeError(errmes)
        s = ''.join(rows)
        d = tomllib.loads(s)
        for kind, infodic in d.items():
            for k, v in infodic.items():
                if kind not in secdict.keys():
                    secdict[kind] = copy.copy(secdict_v_empty)
                if k == 'secretkey':
                    secdict[kind].secretkey = v
                    continue
                if k == 'ercode':
                    secdict[kind].ercode = v
                    continue
        return copy.copy(secdict)


class Main_mk1onepass(object):
    version: str = '0.0.1'
    date: str = '24 Nov 2024'

    def __init__(self):
        self.THESCRNAME = 'mk1onepass'
        self.THEVERSION = self.version
        self.THEDATE = self.date
        self.show_version_mes = ('{0} written by Mike Tuekey.'.format(self.THESCRNAME), '{0}, version {1}'.format(self.THEDATE, self.THEVERSION), '2024, Copyright(C) Mike Turkey, ALL RIGHT RESERVED.', 'Absolutely No Warranty. The Licence is based on the GPLv3 Licence.', 'URL: https://miketurkey.com', '', '  Synopsys:', '    {0} [ --version | --help ]'.format(self.THESCRNAME), '    {0} [OTPKEY] [-c CONF]'.format(
            self.THESCRNAME), '    {0} list [-c CONF]'.format(self.THESCRNAME), '', '  e.g.', '   {0} --version'.format(self.THESCRNAME), '      Show version message.', '   {0} SHOP'.format(self.THESCRNAME), '      Show SHOP one time password. SHOP is keyname.', '   {0} list'.format(self.THESCRNAME), '      Show key names.', '', '  Summary:', '    Timebased One-Time-Password generator.', '')
        return

    def show_version(self):
        for s in self.show_version_mes:
            print(s)
        return

    def main(self):
        mainfunc = Mainfunc
        opt = types.SimpleNamespace(er=False, config='')
        argv1 = ''
        on_config = False
        for arg in sys.argv[1:]:
            if arg == '--version':
                self.show_version()
                exit(0)
            if argv1 == '':
                argv1 = arg
                continue
            if on_config:
                opt.config = arg
                on_config = False
                continue
            if arg == '--er':
                opt.er = True
                continue
            if arg == '-c':
                on_config = True
                continue
        subcmd = ''
        otpkey = ''
        if argv1 in ['list', 'encrypt', 'decrypt', '_findcmdpath']:
            subcmd = argv1
        else:
            otpkey = argv1
        if subcmd == '_findcmdpath':
            self.subcmd_findcmdpath()
            exit(0)
        d = os.getenv('HOME')
        basedir = os.path.join(d, '.mk1onepass')
        if opt.config == '':
            opt.config = os.path.join(basedir, 'config.toml')
        conf = mainfunc.load_config(opt.config)
        gpgmode = False
        if conf.gpgkeyid != '':
            gpg_cmd = mainfunc.findcmd_byPATH('gpg')
            gpgmode = True if gpg_cmd != '' else False
        f = 'onetime.toml.gpg' if gpgmode == True else 'onetime.toml'
        fpath_onepass = os.path.join(basedir, f)
        if os.path.isfile(fpath_onepass) != True:
            errmes = 'Error: Not found the onetime file. [{0}]'.format(
                fpath_onepass)
            print(errmes, file=sys.stderr)
            exit(1)
        if gpgmode:
            args = [gpg_cmd, '-du', conf.gpgkeyid, fpath_onepass]
            try:
                pobj = subprocess.run(args, capture_output=True, timeout=10)
            except:
                errmes = 'Error: oathtool not execute.'
                print(errmes, file=sys.stderr)
            if pobj.returncode == 0:
                s = pobj.stdout.decode('UTF-8')
                templst = [ss+'\n' for ss in s.splitlines()]
                secdict = mainfunc.mk_secdict(templst)
        else:
            with open(fpath_onepass, 'rt')as fp:
                templst = [row for row in fp]
            secdict = mainfunc.mk_secdict(templst)
        if subcmd == 'list':
            for k in secdict.keys():
                print(k)
            exit(0)
        if otpkey not in secdict.keys():
            s = 'Error: Not found the key in onetimepass file. [{0}]'
            errmes = s.format(otpkey)
            print(errmes)
            exit(1)
        oathtool_cmd = mainfunc.findcmd_byPATH('oathtool')
        if oathtool_cmd == '':
            errmes = 'Error: Not found oathtool.'
            print(errmes, file=sys.stderr)
            exit(1)
        args = [oathtool_cmd, '--totp', '--base32', secdict[otpkey].secretkey]
        try:
            pobj = subprocess.run(args, capture_output=True, timeout=1)
        except:
            errmes = 'Error: oathtool not execute.'
            print(errmes, file=sys.stderr)
        if pobj.returncode == 0:
            s = pobj.stdout.decode('UTF-8')
            s = s.strip()
            print(s)
            exit(0)
        else:
            errmes = 'Error: oathtool command error.'
            print(errmes, file=sys.stderr)
            exit(1)

    def subcmd_findcmdpath(self):
        mainfunc = Mainfunc
        subcmd = ''
        findcmd = ''
        for arg in sys.argv[1:]:
            if subcmd == '':
                subcmd = arg
                continue
            if '-' not in arg and findcmd == '':
                findcmd = arg
        cmd = mainfunc.findcmd_byPATH(findcmd)
        if cmd == '':
            exit(1)
        print(cmd)
        exit(0)


def main_mk1onepass():
    maincls = Main_mk1onepass()
    maincls.main()
    exit(0)


if __name__ == '__main__':
    main_mk1onepass()
    exit(0)
