#!/usr/bin/env python3

# Create the host basics locally
import sys
import click
import base64

from loguru import logger
from nacl.public import Box, PublicKey
from .core import *
from .version import VERSION
from .route53 import Route53

lect = """
---
site: <domain>
hosts:
  [hostname]:
    - pubkey: XXXXXXyyyyyyyyyZZZZZ
    - local_networks: 10.1.1.0/24,11.1.1.0/24,2006::/64
    - remote_address: 5.5.5.5
  [hostname]:
    - pubkey: XXXXXXyyyyyyyyyZZZZZ
    - local_networks: 20.1.1.0/24,21.1.1.0/24,2006:1::/64
    - remote_address: 6.6.6.6
"""

lect = """
  {hostname}:
    - pubkey: {pubkey}
    - local_networks: {localnets}
    - remote_address: {remoteaddr}
"""

@click.command()
@click.version_option(VERSION)
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--dry-run','-n', is_flag=True, default=False, help="Do not commit changes.")
@click.argument('infile')
def cli(debug: bool, trace: bool, dry_run: bool, infile: str):
    f''' Setup localhost, provide registration with master controller.
    
    wghost: create and publish a host registration with a wgmesh instance.
    Site setup uses DNS-based or manual hash exchange.
    Output: message that can be imported into site-configurator.
    
    '''
    LoggerConfig(debug, trace)

    # load data
    site, hosts = CheckConfig(*loadconfig(infile))
    CR = '\n'

    'myport == their octet'
    'theirport == myoctet'

    if site.route53:
        r53 = Route53(site)
    else:
        r53 = None
        pass

    if dry_run:
        logger.info(f'No DNS Commits will be made.')
        commit = False
    else:
        commit = True
        pass
    if not len(hosts):
        logger.warn(f'No hosts exists')
    for me in hosts:
        myport = me.endport()
        core = {
            'asn':      me.asn,
            'site':     site.domain,
            'octet':    me.octet,
            'portbase': site.portbase,
            'remote':   str(site.ipv6),
            'hosts': {},
            }
        logger.trace(f'Deploy Host: {me.uuid}')
        for h in hosts:
            if me.uuid == h.uuid: continue
            logger.trace(f'Add host: {h.uuid}')
            logger.trace(f'IPv4: {h.local_ipv4}')
            logger.trace(f'IPv6: {h.local_ipv6}')
            core['hosts'][h.hostname] = { 
                'key': h.public_key,
                'asn': h.asn,
                'localport': h.endport(),
                'remoteport': myport,
                'remote': ','.join([ str(x) for x in h.local_ipv4 + h.local_ipv6 if str(x) > '' ]),
                }
            continue

        MPK = keyimport(me.public_key, PublicKey)
        MBox = Box(site.MSK, MPK)

        yaml = StringYaml()
        host_package  = yaml.dumps(core)
        message = base64.encodebytes( MBox.encrypt( host_package.encode('ascii') ) ).decode()
        logger.debug(f'Plain Data: {host_package}')

        rr_name =  f'{me.uuid}.{site.domain}'
        rr_data = [ f'{i}:{x.strip()}' for i, x in enumerate(message.split('\n')) if x > '' ]

        print(f'|----| ## BEGIN HOST: {me.hostname}')
        print(f'TXT:{CR}{rr_name}{CR}{CR}DATA:')

        if r53:
            logger.debug('commit to route53')
            print('   (using AWS API to save changes...) ')
            r53.save_txt_record(rr_name, rr_data, commit)
            pass
        if debug or not r53:
            print('\n'.join(rr_data))
            print(f'{CR}|----| ###END')
            pass

        print()
        continue
        
    return 0

if __name__ == "__main__":
    sys.exit(Main())
