#!/usr/bin/env python3

# Create the host basics locally
import sys, os
import click
import loguru
import socket
import netifaces
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

def get_local_addresses_with_interface() -> list:
    ''' gather local addresses '''
    ipv4 = []
    ipv6 = []
    for iface in netifaces.interfaces():
        all = netifaces.ifaddresses(iface)
        try:
            all4 = all[netifaces.AF_INET]
        except KeyError:
            all4 = []
        try:
            all6 = all[netifaces.AF_INET6]
        except KeyError:
            all6 = []
        for x in all4:
            ipv4.append({ 'iface': iface, 'addr': x['addr']})
        for x in all6:
            ipv4.append({ 'iface': iface, 'addr': x['addr']})
        continue
    return ipv4, ipv6

def get_local_addresses() -> list:
    ''' gather local addresses '''
    ipv4 = []
    ipv6 = []

    for iface in netifaces.interfaces():
        all = netifaces.ifaddresses(iface)
        try:
            all4 = all[netifaces.AF_INET]
        except KeyError:
            all4 = []
            pass

        try:
            all6 = all[netifaces.AF_INET6]
        except KeyError:
            all6 = []
            pass

        ipv4 = [ x['addr'] for x in all4 if x['addr'].find('%') == -1 and not ipaddress.ip_address(x['addr']).is_private ]
        ipv6 = [ x['addr'] for x in all6 if x['addr'].find('%') == -1 and not ipaddress.ip_address(x['addr']).is_private ]

        if not len(ipv4):
            ipv4 = ''
        elif len(ipv4) == 1:
            ipv4 = ipv4[0]
            pass

        if not len(ipv6):
            ipv6 = ''
        elif len(ipv6) == 1:
            ipv6 = ipv6[0]
            pass

        continue
    return (ipv4, ipv6)


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
@click.option( '--debug','-d', is_flag=True, default=False, help="Activate Debug Logging." )
@click.option( '--trace','-t', is_flag=True, default=False, help="Activate Trace Logging." )
@click.option( '--locus','-l',    default='', help="Manually set Mesh Locus." )
@click.option( '--pubkey','-p',   default='', help="Manually set Mesh Public Key." )
@click.option( '--hostname','-h', default='', help="Override local hostname." )
@click.argument('domain')
def cli(debug: bool, trace: bool, locus: str, pubkey: str, hostname: str, domain: str):
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
    hostconfig = rootconfig(domain, locus, pubkey)
    import pprint
    print('|-----------------------------------|')
    pprint.pprint(hostconfig)

    #Get UUID
    target = f'{hostconfig["host"]["uuid"]}.{domain}'
    try:
        crypt = dns_query(target)
    except:
        logger.error(f"DNS Exception: {target}")
        print()
        raise
        sys.exit(1)
        pass

    try:
        cipher = base64.decodebytes(str(crypt).encode('ascii'))
    except:
        logger.error(f"DNS Exception: {target}")
        print()
        raise
        sys.exit(1)
        pass

    # build Box
    # Loop THrough Contacts
    # Write somethign to disk


    import pprint
    pprint.pprint(nodeconfig)

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