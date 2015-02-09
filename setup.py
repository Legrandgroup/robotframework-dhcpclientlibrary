#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setup script for DHCP Client Robotframework library"""

from __future__ import with_statement
from setuptools import setup
from os.path import abspath, dirname, join

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
    name='robotframework-modbuslibrary',
    version='0.0.1',
    description='Robot Framework library for Modbus',
    long_description=read('README.rst'),
    author='Lionel Ains',
    author_email='lionel.ains@legrand.fr',
    url='https://github.com/Legrandgroup/robotframework-modbuslibrary',
    license='Apache License 2.0',
    keywords='robotframework testing testautomation dhcp bootp client',
    platforms='any',
    classifiers=CLASSIFIERS.splitlines(),
    packages=['rfdhcpclientlib'],
    install_requires=['robotframework', 'pydhcp']
)
