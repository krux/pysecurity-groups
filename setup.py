### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

from setuptools import setup, find_packages

setup(name='ksecurity_groups',
      version="0.0.1",
      description='Library for keeping EC2 security groups synchronized.',
      author='Paul Lathrop',
      author_email='paul@krux.com',
      url='https://github.com/krux/ksecurity_groups',
      packages=find_packages(),
      install_requires=['boto'],
      tests_require=['nose', 'coverage'],
      )
