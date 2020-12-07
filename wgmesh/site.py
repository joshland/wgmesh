#!/usr/bin/env python3

##
## mkhost.py
##

# Create the host basics locally
import sys, os
import click
import loguru
import attr, inspect
import socket
import pprint
import yaml
import base64
import hashlib, uuid
import nacl.utils
import nacl.utils

from loguru import logger
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, genkey, loadkey

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.argument('infile')
def cli(debug, trace, infile):
    f''' Check/Publish base64 to dns '''
    if not debug:
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        pass
    if trace:
        logger.info('Trace')
        logger.remove()
        logger.add(sys.stdout, level='TRACE')
        pass

    site, hosts = CheckConfig(*loadconfig(infile))

    if site.privatekey == '':
        logger.error(f"Global=>privatekey must be set in {infile}")
        print('Fix YAML Config')
        sys.exit(2)
        pass

    try:
        with open(site.privatekey, 'r') as pkey:
            RawMSK = pkey.read()
            logger.debug(f'MSK Loaded {RawMSK}')
            pass
        MSK = PrivateKey( base64.decodestring(RawMSK.encode('ascii')) )
        logger.debug('MSK Decode Succeeded')
    except FileNotFoundError:
        logger.debug('Sitekey does not exist on disk, skipping.')
    except:
        MSK = None
        logger.debug('MSK Decode Failed')
        pass

    if not site.publickey and MSK == None:
        logger.info(f'Generating Private Key: {site.privatekey}')
        if not os.path.exists(site.privatekey):
            ## create the private key
            MSK = genkey(site.privatekey)
            site.publickey = MSK.public_key
            saveconfig(site, hosts, infile)
            pass
        else:
            MSK = loadkey(site.privatekey)
            site.publickey = base64.encodestring(site.publickey.encode())
            pass
        pass

    publish = { 
        'locus': site.locus,
        'publickey': site.publickey,
    }

    y = yaml.dump(publish)

    message = base64.encodebytes(y.encode('ascii')).decode()

    print(f'Raw Text Record: {y}')

    print(f"Fix TXT record for domain {site.domain}, set this: \n\n{message}")
    return 0

if __name__ == "__main__":
    sys.exit(cli())