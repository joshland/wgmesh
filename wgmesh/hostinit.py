#!/usr/bin/env python3

##
## mkhost.py
##

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
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, encrypt

import socket
import pprint
import base64

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--locus','-l', default='', help="Manually set Mesh Locus.")
@click.option('--pubkey','-p', default='', help="Manually set Mesh Public Key.")
@click.option('--hostname','-h', default='', help="Override local hostname.")
@click.option('--domain', '-D', default='', help="Source Domain (TXT lookups for DNS info")
def cli(debug, trace, locus, pubkey, hostname, domain):
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
        dominfo = fetchdomain(domain)

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey == '':
        pubkey = dominfo['pubkey']
        pass

    privfile = f'/etc/wireguard/{locus}_priv'
    pubfile  = f'/etc/wireguard/{locus}_pub'

    if os.path.exists(privfile):
        sk = PrivateKey(base64.decodebytes(open(privfile, 'r').read().encode('ascii')))
        pk = sk.public_key
    else:
        sk = PrivateKey.generate()
        with open(privfile, 'w') as priv:
            priv.write(base64.encodebytes(sk.encode()).decode() )
        pk = sk.public_key
        with open(pubfile, 'w') as pub:
            pub.write(base64.encodebytes(sk.encode()).decode() )

    MPK = PublicKey(base64.decodebytes(pubkey.encode('ascii')))
    try:
        MBox = Box(sk, MPK)
    except:
        MPK = MBox = None
        logger.debug("failed to create MBox, no public key or local private key error.")

    publish = {
        'hostname': hostname,
        'publickey': base64.encodebytes(pk.encode()).decode()
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