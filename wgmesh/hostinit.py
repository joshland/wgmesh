#!/usr/bin/env python3

##
## mkhost.py
##

# Create the host basics locally
import sys, os
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config
import click
import loguru
import attr, inspect
import socket
import pprint
import yaml
import base64
import dns.resolver

from loguru import logger

import nacl.utils
from nacl.public import PrivateKey, Box, PublicKey

import hashlib, uuid

def fetchdomain(domain):
    ''' return the record from the DNS '''
    answer = dns.resolver.query(f"_wg.{domain}","TXT").response.answer[0]
    output = ''
    for item in answer:
        output.append(item)
    output = output.replace('"', '').replace(' ', '')
    text = base64.decodestring(output)
    retval = yaml.safe_load(text)
    for k, v in retval.items():
        if isinstance(v, bytes):
            retval[k] = v.decode()
            continue
        continue
    return retval

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--locus','-l', default='', help="Manually set Mesh Locus.")
@click.option('--pubkey','-p', default='', help="Manually set Mesh Public Key.")
@click.option('--hostname','-h', default='', help="Override local hostname.")
@click.options('--domain', '-d', default='', help="Source Domain (TXT lookups for DNS info")
def cli(debug, trace, locus, pubkey, hostname, domain):
    f''' Update or publish INFILE to Folder specified by OUTPUT {output} for [SITES] '''
    if not debug:
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
    
    dominfo = fetchdomain(domain)

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey = '':
        pubkey = dominfo['pubkey']
        pass

    privfile = f'/etc/wireguard/{locus}_priv'
    pubfile  = f'/etc/wireguard/{locus}_pub'

    if os.path.exists(privfile):
        sk = PrivateKey(base64.decodebyte(open(privfile, 'r').read().encode('ascii')))
        pk = sk.public_key
    else:
        sk = PrivateKey.generate()
        pk = sk.public_key

    try:
        MPK = PublicKey(base64.decodebyte(pubkey.encode('ascii')))
        MBox = Box(sk, MPK)
    except:
        MPK = MBox = None
        logger.debug("failed to create MBox, no public key or local private key error.")

    publish = {
        'hostname': hostname,
        'publickey': base64.encodebytes(pk.encode()).decode()
    }

    print(f'Check output:\n\n')
    pprint.pprint(publish)

    message = yaml.dump(publish)
    
    if MBox:
        output = base64.encodebytes(MBox.encrypt(message))
        print(f'Message to Home: {output}')
        pass

    return 0

if __name__ == "__main__":
    sys.exit(Main())