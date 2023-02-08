#!/usr/bin/env python3

'''
APK static taint analysis

This script relies on our modified version of Androguard.
The user must provide the path to this version in the config.ini file, which we
parse here to avoid duplicated code.
'''

import sys
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

ANDROGUARD_PATH = ''
DEXTRIPADOR_PATH = ''
try:
    ANDROGUARD_PATH = str(config['PATHS']['ANDROGUARD_PATH'])
    DEXTRIPADOR_PATH = str(config['PATHS']['DEXTRIPADOR_PATH'])
except KeyError as exc:
    print('{ERROR} %s' % str(exc))
    sys.exit(1)

sys.path = [ANDROGUARD_PATH] + sys.path
sys.path = [DEXTRIPADOR_PATH] + sys.path
