### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

from setuptools import setup, find_packages

setup(name='pysecurity_groups',
      version="0.0.1",
      description='Library for working with EC2 security groups in bulk.',
      author='Paul Lathrop',
      author_email='paul@krux.com',
      url='https://github.com/krux/pysecurity_groups',
      packages=find_packages(),
      install_requires=['boto'],
      tests_require=['nose', 'coverage'],
      )
