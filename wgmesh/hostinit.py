#!/usr/bin/env python3

# Create the host basics locally
import sys, os
import yaml
import click
import loguru
import nacl.utils
import attr, inspect
import hashlib, uuid

from loguru import logger
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, encrypt, dns_query, keyexport, keyimport

import socket
import pprint
import base64

@click.command()
@click.option('--force','-f', is_flag=True, default=False, help="Overwrite key files (if needed).")
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--locus','-l', default='', help="Manually set Mesh Locus.")
@click.option('--pubkey','-p', default='', help="Manually set Mesh Public Key.")
@click.option('--hostname','-h', default='', help="Override local hostname.")
#@click.option('--domain', '-D', default='', help="Source Domain (TXT lookups for DNS info")
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
    
    if not locus or not pubkey:
        dominfo = dns_query(domain)
        logger.trace(f'domain info: {dominfo}') 

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey == '':
        pubkey = dominfo['publickey']
        pass

    privfile = f'/etc/wireguard/{locus}_priv'
    pubfile  = f'/etc/wireguard/{locus}_pub'

    lsk = None
    lpk = None
    if os.path.exists(privfile):
        logger.debug(f'Private keyfile exists.')
        try:
            #lsk = PrivateKey(base64.decodebytes(open(privfile, 'r').read().encode('ascii')))
            lsk = PrivateKey( keyimport(open(privfile, 'r').read() ))
            logger.debug(f'Private keyfile exists.')
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

    publish = {
        'hostname': hostname,
        'publickey': keyexport(lpk)
    }

    print(f'\nCheck output:')
    pprint.pprint(publish, indent=5)

    message = yaml.dump(publish)
    
    if MBox:
        encmsg = MBox.encrypt( message.encode('ascii') )
        output = base64.encodebytes( encmsg )
        print(f'Message to Home: {output}')
        pass

    print('')
    return 0

if __name__ == "__main__":
    sys.exit(Main())