### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

# Hack to prevent stupid "TypeError: 'NoneType' object is not callable" error
# in multiprocessing/util.py _exit_function when running `python
# setup.py test` (see
# http://www.eby-sarna.com/pipermail/peak/2010-May/003357.html)
try:
    import multiprocessing
except ImportError:
    pass

from setuptools import setup, find_packages

setup(name='pysecurity-groups',
      version="1.0.0",
      description='Library for working with EC2 security groups in bulk.',
      author='Paul Lathrop',
      author_email='paul@krux.com',
      url='https://github.com/krux/pysecurity-groups',
      packages=find_packages(),
      install_requires=['boto', 'argparse', 'IPy', 'ply'],
      setup_requires=['nose'],
      tests_require=['nose'],
      test_suite='nose.collector',
      entry_points={'console_scripts':
                    ['security-groups = pysecurity_groups.cli:main'] },
      )
