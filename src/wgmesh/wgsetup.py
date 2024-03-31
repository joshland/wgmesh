#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
import sys
import typer
import base64
import binascii
import nacl.utils
import dns.resolver

#from wgmesh import core
#from loguru import logger
#from ruamel.yaml import YAML

from nacl.public import Box, PublicKey
from .version import VERSION
from .route53 import Route53
from .crypto import *

app = typer.Typer()

@app.command()
def host(*args, **kwargs):
    ''' do site init stuff '''
    print(f'{args} / {kwargs}')
    # create uuid
    # create keys
    # set hostname
    # public interface
    # trusted interfac
    # site key
    return 0

@app.command()
def publish(*args, **kwargs):
    ''' publish to dns '''
    print(f'{args} / {kwargs}')
    uuid: 2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d
    public_key: o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=
    public_key_file: /etc/wireguard/x707_pub
    private_key_file: /etc/wireguard/x707_priv
    local_ipv4: oob.x707.ashbyte.com
    local_ipv6: ''
    return 0

@app.command()
def deploy(*args, **kwargs):
    ''' do host-operations '''
    print(f'{args} / {kwargs}')
    return 0

if __name__ == "__main__":
    app()

