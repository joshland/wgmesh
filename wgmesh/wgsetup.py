#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
import sys
import typer
import base64
import binascii
import nacl.utils
import dns.resolver

from wgmesh import core
from loguru import logger
from ruamel.yaml import YAML

from nacl.public import Box, PublicKey
from .core import *
from .version import VERSION
from .route53 import Route53

app = typer.Typer()

# Site generation / Maintenance
# Generates a python dictionary with UUENCODE to support host inculcation
#

# Host import / update
# UUID matching
#

@app.command()
def host(*args, **kwargs):
    ''' do site init stuff '''
    print(f'{args} / {kwargs}')
    return 0

@app.command()
def publish(*args, **kwargs):
    ''' publish to dns '''
    print(f'{args} / {kwargs}')
    return 0

@app.host()
def deploy(*args, **kwargs):
    ''' do host-operations '''
    print(f'{args} / {kwargs}')
    return 0

if __name__ == "__main__":
    app()

