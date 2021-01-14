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
from .core import *
from .endpointdb import *

import pprint
import base64

import ipaddress

class StandardIPv4(Exception): pass
class StandardIPv6(Exception): pass
class HostnameRevolves(Exception): pass
class HostnameNoResolve(Exception): pass
class InvalidAddress(Exception): pass


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

def qualifyAddress(addr):
    try:
        address = ipaddress.ip_address(addr)
    except:
        logger.debug(f'{addr} is apparently not an ip address.')
        address = None
        pass

    if address:
        ## treat it like an ip.
        if address.version == 4:
            raise StandardIPv4
        if address.version == 6:
            raise StandardIPv6
        raise InvalidAddress
    else:
        if not(is_valid_hostname(addr)):
            raise InvalidAddress
        try:
            socket.gethostbyname(addr)
            raise HostnameRevolves
        except:
            raise HostnameNoResolve
        pass
    pass

@click.command()
@click.option('--force','-f', is_flag=True, default=False, help="Overwrite key files (if needed).")
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--locus','-l', default='', help="Manually set Mesh Locus.")
@click.option('--addr','-a', default='', help="Endpoint Address(es) - hostname, ipv4, or ipv6.", multiple=True)
@click.option('--pubkey','-P', default='', help="Manually set Mesh Public Key.")
@click.option('--hostname','-h', default='', help="Override local hostname.")
@click.argument('domain')
def cli(force, debug, trace, locus, addr, pubkey, hostname, domain):
    f''' Setup localhost, provide registration with master controller.

    wghost: create and publish a host registration with a wgmesh instance.

    Site setup uses DNS-based or manual hash exchange.

    Output: message that can be imported into site-configurator.
    
    '''
    LoggerConfig(debug, trace)

    if not hostname:
        hostname = socket.gethostname()
        pass
    
    if not locus or not pubkey:
        dominfo = fetch_domain(domain)
        logger.trace(f'domain info: {dominfo}') 
        pass

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey == '':
        pubkey = dominfo['publickey']
        pass

    hostconfig = CheckLostHostConfig(domain, locus, pubkey)

    #hostconfig = load_host_config(domain, locus, pubkey)
    #privfile = f'/etc/wireguard/{locus}_priv'
    #hostconfig.host.public_key_file  = f'/etc/wireguard/{locus}_pub'

    cli_ipaddress = addr
    lsk = None
    lpk = None
    if os.path.exists(hostconfig.host.private_key_file):
        logger.debug(f'Private keyfile exists=>{hostconfig.host.private_key_file}')
        try:
            #lsk = PrivateKey(base64.decodebytes(open(hostconfig.host.private_key_file, 'r').read().encode('ascii')))
            lsk = PrivateKey( keyimport(open(hostconfig.host.private_key_file, 'r').read() ))
            logger.debug(f'Private keyfile loaded successfully.')
            lpk = lsk.public_key
        except:
            logger.error(f'Load or decrypt failed: {hostconfig.host.private_key_file}')
            pass

    if not lsk:
        logger.warning(f'Generating Private Key (this overwrites) ')

        if os.path.exists(hostconfig.host.private_key_file) and not force:
            logger.error(f'{hostconfig.host.private_key_file} exists, but, is unreadable, corrupt, or empty.  Use -f to overwrite.')
            sys.exit(1)

        lsk = PrivateKey.generate()
        with open(hostconfig.host.private_key_file, 'w') as priv:
            logger.trace(f'Writing Secret Key: {hostconfig.host.private_key_file}')
            priv.write( keyexport(lsk) )
            pass

        lpk = lsk.public_key
        with open(hostconfig.host.public_key_file, 'w') as pub:
            logger.trace(f'Writing Public Key: {hostconfig.host.public_key_file}')
            pub.write( keyexport(lpk) )
            pass
        pass

    MPK = PublicKey(base64.decodebytes(pubkey.encode('ascii')))
    try:
        MBox = Box(lsk, MPK)
    except:
        MPK = MBox = None
        logger.debug("failed to create MBox, no public key or local private key error.")
        pass

    ## Message Packet:
    # Inner
    #   {'hostname': '', 'uuid': '', 'publickey': ''}
    # Outer:
    #   {'publickey': '', 'message': <inner encrypted/base64>}

    if len(cli_ipaddress):
        local_ipv4 = []
        local_ipv6 = []
        for addr in cli_ipaddress:
            try:
                qualifyAddress(addr)
            except StandardIPv4:
                logger.trace(f'IPv4 Address Configured: {addr}')
                local_ipv4.append(addr)
            except StandardIPv6:
                logger.trace(f'IPv6 Address Configured: {addr}')
                local_ipv6.append(addr)
            except HostnameRevolves:
                logger.trace(f'Hostname Configured: {addr}')
                local_ipv4.append(addr)
            except HostnameNoResolve:
                logger.trace(f'Hostname Configured: {addr}')
                logger.warning(f'Hostname added, does not resolve: {addr}')
                local_ipv4.append(addr)
                pass
            continue
        logger.trace(f'command-line options for ipaddress: {cli_ipaddress}')
    else:
        local_ipv4, local_ipv6 = get_local_addresses()
        pass

    inner_plain = {
        'hostname': hostname,
        'uuid': hostconfig.host.uuid,
        'public_key': keyexport(lpk),
        'public_key_file': hostconfig.host.public_key_file,
        'private_key_file': hostconfig.host.private_key_file,
        'local_ipv4': ','.join(local_ipv4),
        'local_ipv6': ','.join(local_ipv6),
    }

    inner_crypt  = yaml.dump(inner_plain, Dumper=yaml.RoundTripDumper)
    logger.debug(f'Dump Yaml String {len(inner_crypt)}')
    logger.trace(f'Dump Yaml String {inner_crypt}')
    inner_hidden = base64.encodebytes( MBox.encrypt( inner_crypt.encode('ascii') ) )
    logger.debug(f'Crypt + Encoded String {len(inner_hidden)}')

    outer = {
        'public_key': keyexport(lpk),
        'message': inner_hidden,
    }

    logger.trace(f'Publising dict: {outer}')

    if debug:
        print(f'\nCheck output:')
        pprint.pprint(outer, indent=5)

    outer_plain   = yaml.dump(outer, Dumper=yaml.RoundTripDumper)
    output_hidden = base64.encodebytes( outer_plain.encode('ascii') ).decode().replace('\n','')

    print()
    print(f'Message to Home: {output_hidden}')

    print('')
    return 0

if __name__ == "__main__":
    sys.exit(Main())