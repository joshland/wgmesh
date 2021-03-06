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
import base64
import binascii
import hashlib, uuid
import nacl.utils
import nacl.utils
import dns.resolver

from wgmesh import core
from loguru import logger
from ruamel import yaml
from ruamel.yaml import RoundTripLoader, RoundTripDumper
from nacl.public import PrivateKey, Box, PublicKey
from .core import *

# Site generation / Maintenance
# Generates a python dictionary with UUENCODE to support host inculcation
#

# Host import / update
# UUID matching
#

CR="\n"
def siteActivation(debug: bool, trace: bool, site: core.Sitecfg, hosts: core.Host) -> list:
    '''

    Check and publish mesh domain activation.

    '''
    if site.privatekey == '':
        logger.error(f"Global=>privatekey must be set in {infile}")
        print('Fix YAML Config')
        sys.exit(2)
        pass

    publish = { 
        'locus': site.locus,
        'publickey': keyexport(site.publickey),
    }

    y = yaml.dump(publish, Dumper=yaml.RoundTripDumper)
    message = base64.encodebytes(y.encode('ascii')).decode()

    try:
        current = fetch_domain(site.domain)
    except dns.resolver.NXDOMAIN:
        logger.debug(f'Domain reports no record found. Request: TXT:{site.domain}')
        current = {}
    except binascii.Error:
        logger.error(f'Bindecode base64 error.')
        raise
        sys.exit(1)
    except:
        logger.error("failed to decode dns record.")
        current = {}
        pass

    if current == publish:
        logger.debug(f"Existing Records for {site.domain} are correct.")
        logger.debug(f"Existing Records: {current}.")
        logger.debug(f"Calculated Records: {publish}.")
        pass

    print(f'Site: {site.domain}')
    found = False
    if publish == current:
        print()
        print(f"  Check:\n    DNS Records OK! ({site.domain})")
        print()
        found = True
    else:
        print()
        print(f"  Check:\n\n    DNS Records Incorrect: ({site.domain})")
        print('\n  Please update the TXT Record before attempting to configure hosts.')
        print()

        if len(current):
            print(f'  Decoded TXT Records: (current)')
            for k, v in current.items():
                print(f'   {k}: {v}')
                continue
            pass

        print(f'  Decoded TXT Record: (proposed)')
        for k, v in publish.items():
            print(f'   {k}: {v}')
            continue
        print()
        pass

    if debug or trace or not found:
        print() 
        print(f'New DNS Text record:\n\n{site.domain}')
        print()
        print('Content of Text Record:\n')
        for x, l in enumerate(message.split('\n')):
            if l.strip() == "": continue
            print(f'{x}:{l.strip()}')
            continue
        print('')
        pass

    return site, hosts

def hostImport(data: str, site: core.Sitecfg, hosts: list) -> list:
    ''' import/update a host from a site '''

    outer_message = base64.decodebytes( data.encode('ascii') ).decode()
    logger.debug(f'Host import: {data}')
    outer = yaml.load(outer_message, Loader=yaml.RoundTripLoader)
    logger.trace(f'Outer message: {outer}')
    HPub = keyimport( outer['public_key'], PublicKey)
    logger.trace(f'HPub/{HPub} -- SKey/{site.MSK}')
    SBox = Box(site.MSK, HPub)

    inner_decoded = base64.decodebytes( outer['message'] )
    inner_message = SBox.decrypt( inner_decoded )
    inner = yaml.load (inner_message, Loader=yaml.RoundTripLoader)
    logger.debug(f'Host Decode: {inner}')
    
    key = inner['public_key'].lower()

    hostname = inner['hostname'].lower()
    del inner['hostname']
    host = Host(hostname, site, **inner)

    found = False
    for x in hosts:
        if x.uuid == host.uuid:
            x.update(host)
            found = True
            continue
        continue

    if not found:
        hosts.append(host)
        pass

    return CheckConfig(site, hosts)

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--hostimport','-i', default='', help="Import Hostfile.")
@click.argument('infile')
def cli(debug, trace, hostimport, infile):
    f''' Check/Publish base64 to dns '''
    LoggerConfig(debug, trace)

    site, hosts = CheckConfig(*loadconfig(infile))
    if hostimport:
        logger.debug(f'mode: Host Import.')
        site, hosts = hostImport(hostimport, site, hosts)
    else:
        logger.debug(f'Site Activation.')
        site, hosts = siteActivation(debug, trace, site, hosts)
        pass
    saveconfig(site, hosts, infile)
    return 0

if __name__ == "__main__":
    sys.exit(cli())
