# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Joshua Schmidlkofer <joshua.schmidlkofer@erickson.is>
# All rights reserved.
#
# This software is licensed as described in the file LICENSE, which
# you should have received as part of this distribution.
#
# Author: Joshua M. Schmidlkofer <joshua.schmidlkofer@erickson.is>
import os
from setuptools import setup, find_packages
from importlib import import_module

here = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(here, 'README.md')
README = ''
if os.path.exists(readme_path):
    with open(readme_path) as f:
        README = f.read()

v = import_module('version')

requires = [
    'wheel',
    'attrs',
    'click',
    'dnspython',
    'ifaddr',
    'loguru',
    'natsort',
    'netaddr',
    'pynacl',
    'route53',
    'ruamel.yaml',
    'six',
    'jinja2'
]

test_requires = requires

setup(name='wgmesh',
      version=v.VERSION,
      description='Wireguard Mesh Maker',
      long_description=README,
      classifiers=[
          "Environment :: Console",
          "Intended Audience :: Information Technology",
          "License :: OSI Approved :: MIT License",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: 3.8",
          "Programming Language :: Python :: 3.9",
          "Operating System :: POSIX :: Linux",
          "Topic :: Internet",
          "Topic :: System :: Networking",
          "Development Status :: 4 - Beta",
          "Natural Language :: English",
      ],
      author='Joshua M. Schmidlkofer',
      author_email='joshua.schmidlkofer@erickson.is',
      url='https://github.com/joshland/wgmesh',
      keywords='wireguard frr',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      entry_points="""\
      [console_scripts]
      wgconfig = wgmesh:config_cli
      wgdeploy = wgmesh:deploy_cli
      wghost   = wgmesh:host_cli
      wgpub    = wgmesh:pub_cli
      wgsite   = wgmesh:site_cli
      """,
      )
