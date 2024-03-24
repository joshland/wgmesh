#!/usr/bin/env python

import click
import sys, os

from loguru import logger
from .core import LoggerConfig, generate_key, keyexport
from .version import VERSION

import nacl.utils
from nacl.public import PrivateKey, SealedBox

struct = {
    'global': {
        'alerts': 'alerts@example.com',
        'domain': 'example.com',
        'ipv6': 'fd86:ea04:1116::/64',
        # Examples: https://simpledns.plus/private-ipv6
        'locus': 'wgmesh',
        'portbase': '21100',
        'asn_range': '64512:64525',
        'publickey': '',
        'privatekey': 'site.key',
    },
    'hosts': {},
}

@click.command()
@click.version_option(VERSION)
@click.option( '--debug',    '-d', default=False, is_flag=True, help="Activate Debug Logging." )
@click.option( '--trace',    '-t', default=False, is_flag=True, help="Activate Trace Logging." )
@click.option( '--dry-run',  '-n', default=False, is_flag=True, help="Don't write any files."  )
@click.option( '--pub',      '-p', default='', help="Pub file.vManually set public key" )
@click.option( '--key',      '-k', default='', help="Manually set private key" )
@click.option( '--force',    '-f', default=False, is_flag=True, help='Force overwriting')
@click.argument('filename', default='')
def keygen(debug: bool, trace: bool, dry_run: bool, pub: str, key: str, force: bool, filename: str):
    path = os.path.dirname(filename)
    fname = os.path.basename(filename)
    if path:
        if not os.path.exist(path):
            logger.error(f'{path} does not exist')
            sys.exit(4)
    if os.path.exists(filename) and not force:
        logger.error(f'{filename} exists, abort')
        sys.exit(3)
        pass
    newkey = generate_key()
    public = keyexport(newkey.public_key)
    private = keyexport(newkey)

    if dry_run or filename in ['-', '']:
        print(f'Public Key: {public}')
        print(f'Private Key: {private}')
        sys.exit(1)
        pass

    with open(f'{filename}.key', 'w') as keyfile:
        logger.info(f'Writing file {filename}.key...')
        keyfile.write(private)
        pass

    with open(f'{filename}.pub', 'w') as keyfile:
        logger.info(f'Writing file {filename}.pub...')
        keyfile.write(public)
        pass

    return 0
    
@click.command()
@click.version_option(VERSION)
@click.option( '--debug',    '-d', default=False, is_flag=True, help="Activate Debug Logging." )
@click.option( '--trace',    '-t', default=False, is_flag=True, help="Activate Trace Logging." )
@click.option( '--dry-run',  '-n', default=False, is_flag=True, help="Don't write any files."  )
@click.option( '--gen-key',  '-g', default=False, is_flag=True, help="Generate new site key."  )
@click.option( '--locus',    '-l', default='', help="Manually set Mesh Locus. (Familiar tunnel name)"      )
@click.option( '--pub',      '-p', default='', help="Manually set public key" )
@click.option( '--key',      '-k', default='', help="Manually set private key" )
@click.option( '--ipv4',     '-4', default='', help="Set private tunnel ipv4 address (optional)."      )
@click.option( '--ipv6',     '-6', default='', help="Set private tunnel routing ipv6 address (optional)."      )
@click.option( '--asn',      '-a', default='4200000000:4200001000', help='Specify ASN Range.')
@click.option( '--home',     '-h', default='/etc/wireguard', help='Working Directory.')
@click.option( '--force',    '-f', default=False, is_flag=True, help='Force overwriting')
@click.argument('domain')
def cli(debug: bool, trace: bool, dry_run: bool, gen_key: bool, locus: bool, pub: str, key: str, ipv4: str, ipv6: str,
        asn: str, home: str, domain: str):
    
    #use keys to update global config
    LoggerConfig(debug, trace)

    if not locus:
        logger.error(f'Locus is a required argument')
        return 3

    if not os.path.exists(home):
        logger.error(f"Home {home} does not exist.")
        return 4

    if gen_key:
        # check for {home}/{locus}.privkey
        # check for -for value in iterable:
        private = PrivateKey.generate()
        pass

    if key and pub:
        ## compare and validate the public and private key
        ## 
        logger.error(f"Todo: Fix ability to compare pub/priv keys ")

    if Key:
        pass
    logger.trace(f'Loading Public Key: {key}')


    return 0

if __name__ == "__main__":
    sys.exit(cli())
