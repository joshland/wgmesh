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
from wgcore import loadconfig, saveconfig, CheckConfig, gen_local_config

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.argument('infile')
def cli(debug, trace, infile):
    f''' Check/Publish base64 to dns '''
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

    site, hosts = CheckConfig(*loadconfig(infile))

    publish = { 
        'locus': site.locus,
        'publickey': site.publickey.encode().decode(),
    }

    y = yaml.dump(publish)

    message = base64.encodebytes(y.encode('ascii')).decode()

    print(f"Fix TXT record for domain {site.domain}, set this: \n\n{message}")
    return 0

if __name__ == "__main__":
    sys.exit(cli())