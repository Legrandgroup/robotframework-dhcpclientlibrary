#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setup script for DHCP Client Robotframework library"""

from __future__ import with_statement
from setuptools import setup
from os.path import abspath, dirname, join

from rfdhcpclientlib import __lib_version__

def read(fname):
    """read and return fname file content"""
    curdir = dirname(abspath(__file__))
    with open(join(curdir, fname)) as filename:
        return filename.read()

CLASSIFIERS = """
Development Status :: 3 - Alpha
License :: OSI Approved :: Apache Software License
Operating System :: OS Independent
Programming Language :: Python
Topic :: Software Development :: Testing
"""[1:-1]

setup(
    name='robotframework-dhcpclientlibrary',
    version=__lib_version__,
    description='This library allows RobotFramework to interact with a DHCP server and to handle DHCP events using RobotFramework keywords',
    long_description=read('README.md'),
    author='Lionel Ains',
    author_email='lionel.ains@legrand.fr',
    url='https://github.com/Legrandgroup/robotframework-dhcpclientlibrary',
    license='Apache License 2.0',
    keywords='robotframework testing testautomation dhcp bootp client',
    platforms='any',
    classifiers=CLASSIFIERS.splitlines(),
    packages=['rfdhcpclientlib'],
    scripts=['scripts/DBusControlledDhcpClient.py'],
    install_requires=['robotframework', 'pydhcplib']
)
