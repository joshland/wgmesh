# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Joshua Schmidlkofer <joshua.schmidlkofer@erickson.is>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
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

# Load version from version module (this might be a bad idea, not sure)
v = import_module('version')

requires = [
    'wheel',
    'attrs',
    'click',
    'dnspython',
    'ifaddr',
    'loguru',
    'natsort',
    'pynacl',
    'route53',
    'ruamel.yaml',
    'six',
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
          "Programming Language :: Python :: 3 :: Only",
          "Operating System :: Linux",
          "Topic :: Utilities",
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
      wgfrr    = wgmesh:frr_cli
      wgdeploy = wgmesh:deploy_cli
      wghost   = wgmesh:host_cli
      wgpub    = wgmesh:pub_cli
      wgsite   = wgmesh:site_cli
      """,
      )
