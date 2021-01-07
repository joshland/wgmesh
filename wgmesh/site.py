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
import hashlib, uuid
import nacl.utils
import nacl.utils
import dns.resolver

from wgmesh import core
from loguru import logger
from ruamel import yaml
from ruamel.yaml import RoundTripLoader, RoundTripDumper
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import Host, loadconfig, saveconfig, CheckConfig, gen_local_config, genkey, loadkey, dns_query, keyexport, keyimport

# Site generation / Maintenance
# Generates a python dictionary with UUENCODE to support host inculcation
#

# Host import / update
# UUID matching
#

def siteActivation(site: core.Sitecfg, hosts: core.Host) -> list:
    ''' perform site activiation process '''
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
        current = dns_query(site.domain)
    except dns.resolver.NXDOMAIN:
        logger.debug(f'Domain reports no record found. Request: TXT:{site.domain}')
        current = {}
    except:
        logger.error("failed to decode dns record.")
        current = {}
        pass

    if current == publish:
        logger.debug(f"Existing Records for {site.domain} are correct.")
        logger.debug(f"Existing Records: {current}.")
        logger.debug(f"Calculated Records: {publish}.")
        pass


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

    return site, hosts

def hostImport(data: str, site: core.Sitecfg, hosts: list) -> list:
    ''' import/update a host from a site '''

    outer_message = base64.decodebytes( data.encode('ascii') ).decode()
    logger.debug(f'Host import: {data}')
    outer = yaml.load(outer_message, Loader=yaml.RoundTripLoader)
    logger.trace(f'Outer message: {outer}')
    HPub = PublicKey( keyimport( outer['public_key'] ))
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

    return site, hosts

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--hostimport','-i', default='', help="Import Hostfile.")
@click.argument('infile')
def cli(debug, trace, hostimport, infile):
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
    if hostimport:
        logger.debug(f'mode: Host Import.')
        site, hosts = hostImport(hostimport, site, hosts)
    else:
        logger.debug(f'Site Activation.')
        site, hosts = siteActivation(site, hosts)
        pass
    saveconfig(site, hosts, infile)
    return 0

if __name__ == "__main__":
    sys.exit(cli())