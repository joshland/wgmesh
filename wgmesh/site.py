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
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, genkey, loadkey, dns_query, keyexport

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

    publish = { 
        'locus': site.locus,
        'publickey': keyexport(site.publickey),
    }

    y = yaml.dump(publish)

    message = base64.encodebytes(y.encode('ascii')).decode()

    try:
        current = dns_query(site.domain)
    except:
        logger.error("failed to decode dns record.")
        current = {}
        pass

    if current == publish:
        logger.debug(f"Existing Records for {site.domain} are correct.")
        logger.debug(f"Existing Records: {current}.")
        logger.debug(f"Calculated Records: {publish}.")
        pass

    saveconfig(site, hosts, infile)

    print()
    print(f'Caluclated Records:')
    for k, v in publish.items():
        print(f'   {k}: {v}')
        continue

    print()
    print(f'Existing Records:')
    for k, v in current.items():
        print(f'   {k}: {v}')
        continue

    print()
    print(f'DNS TXT Record for {site.domain}:')
    print()
    print('"""')
    for l in message.split('\n'):
        print(f'{l.strip()}')
        continue
    print('"""')

    return 0

if __name__ == "__main__":
    sys.exit(cli())