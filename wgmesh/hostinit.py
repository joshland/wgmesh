#!/usr/bin/env python3

# Create the host basics locally
import sys, os
import yaml
import click
import loguru
import socket
import netifaces
import nacl.utils
import attr, inspect
import hashlib, uuid

from loguru import logger
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, encrypt, dns_query, keyexport, keyimport
from wgmesh.core import rootconfig

import pprint
import base64


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
        try:
            all6 = all[netifaces.AF_INET6]
        except KeyError:
            all6 = []
        for x in all4:
            ipv4.append((iface, x['addr']))
        for x in all6:
            ipv6.append((iface, x['addr']))
        continue
    return ipv4, ipv6


@click.command()
@click.option('--force','-f', is_flag=True, default=False, help="Overwrite key files (if needed).")
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--locus','-l', default='', help="Manually set Mesh Locus.")
@click.option('--pubkey','-p', default='', help="Manually set Mesh Public Key.")
@click.option('--hostname','-h', default='', help="Override local hostname.")
@click.argument('domain')
def cli(force, debug, trace, locus, pubkey, hostname, domain):
    f''' Setup localhost, provide registration with master controller.'''
    if debug:
        logger.info('Debug')
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        pass
    if trace:
        logger.info('Trace')
        logger.remove()
        logger.add(sys.stdout, level='TRACE')
        pass

    if not hostname:
        hostname = socket.gethostname()
        pass
    
    if not locus or not pubkey:
        dominfo = dns_query(domain)
        logger.trace(f'domain info: {dominfo}') 
        pass

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey == '':
        pubkey = dominfo['publickey']
        pass

    hostconfig = rootconfig(domain, locus, pubkey)

    privfile = f'/etc/wireguard/{locus}_priv'
    pubfile  = f'/etc/wireguard/{locus}_pub'

    lsk = None
    lpk = None
    if os.path.exists(privfile):
        logger.debug(f'Private keyfile exists=>{privfile}')
        try:
            #lsk = PrivateKey(base64.decodebytes(open(privfile, 'r').read().encode('ascii')))
            lsk = PrivateKey( keyimport(open(privfile, 'r').read() ))
            logger.debug(f'Private keyfile loaded successfully.')
            lpk = lsk.public_key
        except:
            logger.error(f'Load or decrypt failed: {privfile}')
            pass

    if not lsk:
        logger.warning(f'Generating Private Key (this overwrites) ')

        if os.path.exists(privfile) and not force:
            logger.error(f'{privfile} exists, but, is unreadable, corrupt, or empty.  Use -f to overwrite.')
            sys.exit(1)

        lsk = PrivateKey.generate()
        with open(privfile, 'w') as priv:
            logger.trace(f'Writing Secret Key: {privfile}')
            priv.write( keyexport(lsk) )
            pass

        lpk = lsk.public_key
        with open(pubfile, 'w') as pub:
            logger.trace(f'Writing Public Key: {pubfile}')
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

    inner_plain = {
        'hostname': hostname,
        'uuid': hostconfig['host']['uuid'],
        'publickey': keyexport(lpk)
    }

    inner_crypt  = yaml.dump(inner_plain)
    logger.trace(f'Dump Yaml String {len(inner_crypt)}')
    inner_hidden = base64.encodebytes( MBox.encrypt( inner_crypt.encode('ascii') ) )
    logger.trace(f'Crypt + Encoded String {len(inner_hidden)}')

    outer = {
        'publickey': keyexport(lpk),
        'message': inner_hidden,
    }

    logger.trace(f'Publising dict: {outer}')

    print(f'\nCheck output:')
    pprint.pprint(outer, indent=5)

    outer_plain   = yaml.dump(outer)
    output_hidden = base64.encodebytes( outer_plain.encode('ascii') ).decode().replace('\n','')

    print()
    print(f'Message to Home: {output_hidden}')

    print('')
    return 0

if __name__ == "__main__":
    sys.exit(Main())