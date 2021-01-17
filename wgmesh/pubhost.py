#!/usr/bin/env python3

# Create the host basics locally
import sys, os
import click
import loguru
import socket
import nacl.utils
import attr, inspect
import hashlib, uuid

from loguru import logger
from ruamel import yaml
from ruamel.yaml import RoundTripLoader, RoundTripDumper
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import *

import pprint
import base64

import ipaddress


lect = """
---
site: <domain>
hosts:
  [hostname]:
    - pubkey: XXXXXXyyyyyyyyyZZZZZ
    - local_networks: 10.1.1.0/24,11.1.1.0/24,2006::/64
    - remote_address: 5.5.5.5
  [hostname]:
    - pubkey: XXXXXXyyyyyyyyyZZZZZ
    - local_networks: 20.1.1.0/24,21.1.1.0/24,2006:1::/64
    - remote_address: 6.6.6.6
"""

lect = """
  {hostname}:
    - pubkey: {pubkey}
    - local_networks: {localnets}
    - remote_address: {remoteaddr}
"""

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.argument('infile')
def cli(debug: bool, trace: bool, infile: str):
    f''' Setup localhost, provide registration with master controller.
    
    wghost: create and publish a host registration with a wgmesh instance.
    Site setup uses DNS-based or manual hash exchange.
    Output: message that can be imported into site-configurator.
    
    '''
    LoggerConfig(debug, trace)

    # load data
    site, hosts = CheckConfig(*loadconfig(infile))
    CR = '\n'

    'myport == their octet'
    'theirport == myoctet'

    for me in hosts:
        uuid = me.uuid
        myport = me.endport()
        myaddrs = ','.join([str(me.tunnel_ipv4), str(me.tunnel_ipv6)])
        core = {
            'site':     site.domain,
            'octet':    me.octet(),
            'portbase': site.portbase,
            'remote':   str(site.ipv6),
            'hosts': {},
            }
        logger.trace(f'Deploy Host: {me.uuid}')
        for h in hosts:
            if me.uuid == h.uuid: continue
            logger.trace(f'Add host: {h.uuid}')
            core['hosts'][h.hostname] = { 
                'key': h.public_key,
                'localport': h.endport(),
                'remoteport': myport,
                #'local': myaddrs,
                'remote': ','.join([ x for x in h.local_ipv4 + h.local_ipv6 if x > '' ]),
                }
            continue

        MPK = PublicKey(base64.decodebytes(me.public_key.encode('ascii')))
        MBox = Box(site.MSK, MPK)

        host_package  = yaml.dump(core, Dumper=yaml.RoundTripDumper)
        # yamldump core
        # uuencode core
        message = base64.encodebytes( MBox.encrypt( host_package.encode('ascii') ) ).decode()
        logger.debug(f'Plain Data: {host_package}')
        print(f'|----| ## BEGIN HOST: {me.hostname}')
        print(f'TXT:{CR}{me.uuid}.{site.domain}{CR}{CR}DATA:')
        for i, l in enumerate(message.split('\n')):
            if l.strip() == "": continue
            print(f'{i}:{l.strip()}')
            continue
        print(f'{CR}|----| ###END ')
        print()
        continue
        
    return 0

if __name__ == "__main__":
    sys.exit(Main())