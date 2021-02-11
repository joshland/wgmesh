#!/usr/bin/env python3

# Create the host basics locally
import sys, os
import click
import loguru
import socket
import nacl.utils
import attr, inspect
import hashlib, uuid
import netaddr

from loguru import logger
from ruamel import yaml
from ruamel.yaml import RoundTripLoader, RoundTripDumper
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import *
from wgmesh import HostDB
from wgmesh.templates import render, shorewall_interfaces, shorewall_rules, namespace_start
from .endpointdb import *

import pprint
import base64

import ipaddress

class MixedInterface(Exception): pass
class NoInterface(Exception): pass

def find_interfaces():
    ''' return the public interface '''
    all = get_local_addresses_with_interfaces()
    public4  = []
    trust4 = []
    public6  = []
    trust6 = []
    retval = (None, None)

    for iface, addr in all[0] + all[1]:
        logger.trace(f'Located IP Address: {iface} / {addr}')
        addr = ipaddress.ip_address(addr)
        if addr.version == 4:
            apub = public4
            atru = trust4
        else:
            apub = public6
            atru = trust6
            pass

        if addr.is_private:
            if iface in atru: continue
            if getattr(addr, 'is_link_local', False):
                continue
            if iface in apub: 
                raise MixedInterface
            logger.debug(f'Private address {addr} on interface {iface}.')
            atru.append(iface)
        else:
            if iface in apub: continue
            if iface in atru:
                raise MixedInterface
            logger.debug(f'Public address {addr} on interface {iface}.')
            apub.append(iface)
            continue
        continue

    if len(public4) == 1 and len(trust4) == 1:
        retval = (public4[0], trust4[0])
    elif len(public6) == 1 and len(trust6) == 1:
        retval = (public6[0], trust6[0])
    elif len(public6) == 1 and len(trust4) == 1:
        retval = (public6[0], trust4[0])
        pass

    return retval

def find_trust():
    ''' return the trust(private) interface '''
    public, private = find_interfaces()
    if private:
        return private
    else:
        raise NoInterface

def find_public():
    ''' return the trust(private) interface '''
    public, private = find_interfaces()
    if public:
        return public
    else:
        raise NoInterface

@click.command()
@click.option( '--debug',    '-d', default=False, is_flag=True, help="Activate Debug Logging." )
@click.option( '--trace',    '-t', default=False, is_flag=True, help="Activate Trace Logging." )
@click.option( '--dry-run',  '-n', default=False, is_flag=True, help="Don't write any files."  )
@click.option( '--locus',    '-l', default='', help="Manually set Mesh Locus."      )
@click.option( '--pubkey',   '-p', default='', help="Manually set Mesh Public Key." )
@click.option( '--hostname', '-h', default='', help="Override local hostname."      )
@click.option( '--inbound',  '-i', default='', help="Inbound interface."  )
@click.option( '--outbound', '-o', default='', help="Outbound interface." )
@click.option( '--trust',    '-T', default='', help="Trust interface."    )
@click.option( '--trustip',  '-I', default='', help="Trust interface Ip Address + CIDR."    )
@click.argument('domain')
def cli(debug: bool, trace: bool, dry_run: bool, locus: str, pubkey: str, hostname: str,
        inbound: str, outbound: str, trust: str, trustip: str, domain: str):
    f''' Setup localhost, provide registration with master controller.

    wgconfig: apply local configuration settings.

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

    #Guess or not?
    guess = False
    kwargs = {}
    if guess:
        if not inbound:
            try:
                template_args['interface_public'] = find_public()
            except NoInterface:
                logger.error('No public interface found.')
                sys.exit(1)
        else:
            template_args['interface_public'] = inbound
            pass

        if not trust:
            template_args['interface_trust'] = find_trust()
        else:
            template_args['interface_trust'] = trust
            pass

        if not outbound:
            template_args['interface_outbound'] = 'veth0'
        else:
            template_args['interface_outbound'] = outbound
            pass
    else:
        if inbound:
            kwargs['public'] = inbound
        if outbound:
            kwargs['outbound'] = outbound
        if trust:
            kwargs['trust'] = trust
        if trustip:
            addr = netaddr.IPNetwork(trustip)
            kwargs['trustip'] = trustip
            pass

    hostconfig = CheckLocalHostConfig(domain, locus, pubkey, **kwargs)

    return 0

if __name__ == "__main__":
    sys.exit(Main())