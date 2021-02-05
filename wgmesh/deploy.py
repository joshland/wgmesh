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
from wgmesh import HostDB
from .endpointdb import *

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

wire_template = """
#
# Peering template generated template for {myhost} => {Hostname}
#
[Interface]
PrivateKey = {private_key}
Address    = {tunnel_addresses}
ListenPort = {local_port}

# {Hostname}
[Peer]
PublicKey  = {public_key}
Endpoint   = {remote_address}
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepAlive = 25
"""

@click.command()
@click.option( '--debug','-d', is_flag=True, default=False, help="Activate Debug Logging." )
@click.option( '--trace','-t', is_flag=True, default=False, help="Activate Trace Logging." )
@click.option( '--dry-run','-n', is_flag=True, default=False, help="Don't write any files." )
@click.option( '--locus','-l', default='', help="Manually set Mesh Locus." )
@click.option( '--pubkey','-p', default='', help="Manually set Mesh Public Key." )
@click.option( '--hostname','-h', default='', help="Override local hostname." )
@click.argument('domain')
def cli(debug: bool, trace: bool, dry_run: bool, locus: str, pubkey: str, hostname: str, domain: str):
    f''' Setup localhost, provide registration with master controller.

    wgdeploy: deploy wireguard and FRR configuration.

    '''
    LoggerConfig(debug, trace)

    if not locus or not pubkey:
        try:
            dominfo = fetch_domain(domain)
        except:
            logger.error(f'DNS Query Timeout: {domain}')
            sys.exit(1)
        logger.trace(f'domain info: {dominfo}') 
        pass

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey == '':
        pubkey = dominfo['publickey']
        pass

    #hostconfig
    hostconfig = CheckLostHostConfig(domain, locus, pubkey)
    import pprint
    print(f'|-----------------------------------|')
    pprint.pprint(hostconfig)

    #Get UUID
    target = f'{hostconfig.host.uuid}.{domain}'
    try:
        crypt = dns_query(target)
    except:
        logger.error(f"DNS Exception: {target}")
        print()
        raise
        sys.exit(1)
        pass

    message = decrypt(hostconfig.host.SSK, hostconfig.site.PPK, crypt)[2]
    o = yaml.load(message, Loader=yaml.RoundTripLoader)

    print("HostConfig:")
    pprint.pprint(hostconfig.publish(), indent=2)
    print()
    print('Published:')
    pprint.pprint(o, indent=2)

    portbase = o['portbase']
    site = o['site']
    tunnel, cidr = o['remote'].split('/')
    mykey = open(hostconfig.host.private_key_file, 'r').read().strip()

    for index, item in enumerate(o['hosts'].items()):
        host, values = item
        remotes = ''
        if len(values['remote']):
            addrs = values['remote'].split(',')
            remotes = (',').join( [ f"{str(x)}:{values['remoteport']}" for x in addrs ] )
            pass
        epaddr = f'{tunnel}{index}:{o["octet"]}/{cidr}'
        fulfill = {
            'myhost':           hostconfig.host.hostname,
            'private_key':      mykey,
            'tunnel_addresses': epaddr,
            'local_port':       values['localport'],
            'Hostname':         host,
            'public_key':       values['key'],
            'remote_address':   remotes,
        }

        print()
        print(f'writing: /etc/wireguard/wg{index}.conf')
        if dry_run:
            logger.info(f'Dry-run Mode.')
            print(wire_template.format(**fulfill))
        else:
            with open(f'/etc/wireguard/wg{index}.conf', 'w') as writer:
                writer.write(wire_template.format(**fulfill))
                pass
            pass
        continue

    # build Box
    # Loop THrough Contacts
    # Write somethign to disk

    #Get Domain

    # Deploy Configuration

    ## Fetch Domain Settings ffrom DNS (or import)

    # local config load -> get UUID
    # We need port settings
    # /etc/wireguard/(that file).yaml
    
    # build wireguard config

    return 0

if __name__ == "__main__":
    sys.exit(Main())