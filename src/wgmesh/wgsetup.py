#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
import os
import sys
from io import StringIO
from glob import glob

import typer as t
from loguru import logger
from typing import Annotated
from nacl.public import Box, PublicKey

from .endpointdata import Endpoint
from .lib import LoggerConfig, load_endpoint_config, save_endpoint_config, fetch_and_decode_record
from .version import VERSION
from .route53 import Route53
from .crypto import *
from .hostlib import get_local_addresses_with_interfaces

app = t.Typer()

@app.command()
def init(locus:           Annotated[str, t.Argument(help='Site locus')],
         domain:          Annotated[str, t.Argument(help='Locus domain name')],
         config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")]          = '/etc/wireguard',
         trust_iface:     Annotated[str,   t.Option(help='Trusted Interface')]       = False, 
         trust_addrs:     Annotated[str,   t.Option(help='Trusted Addresses (delimit w/ comma')]       = False, 
         public_iface:    Annotated[str,   t.Option(help='Public Interface')]       = False, 
         public_addrs:    Annotated[str,   t.Option(help='Public Addresses (delimt w/ comma')]       = False, 
         force:           Annotated[bool,  t.Option(help='force overwrite')]       = False,
         dryrun:          Annotated[bool,  t.Option(help='do not write anything')] = False,
         debug:           Annotated[bool,  t.Option(help='debug logging')]         = False,
         trace:           Annotated[bool,  t.Option(help='trace logging')]         = False):
    ''' do site init stuff '''
    LoggerConfig(debug, trace)

    cfg_file = f'{domain}.yaml'
    pubkey = f'{locus}_endpoint_pub'
    privkey = f'{locus}_endpoint_priv'
    endpoint_file  = os.path.join(config_path, cfg_file)
    endpoint_pubf  = os.path.join(config_path, pubkey)
    endpoint_privf = os.path.join(config_path, privkey)

    for x in (endpoint_file, endpoint_pubf, endpoint_privf):
        if os.path.exists(x) and not (force or dryrun):
            logger.error(f"{x} exists, aborting (use --force to overwrite)")
            sys.exit(4)
    
    locus_info = fetch_and_decode_record(domain)
    if not locus_info:
        logger.error(f"Failed to fetch record, aborting")
        sys.exit(1)

    ep = Endpoint(locus, domain, locus_info['publickey'],
                  secret_key_file = endpoint_privf, public_key_file = endpoint_pubf)
    
    if trust_iface:
        ep.trust_iface = trust_iface
    if public_iface:
        ep.public_iface = public_iface
    if trust_addrs:
        ep.trust_address = trust_addrs.split(',')
    if public_addrs:
        ep.public_address = public_addrs.split(',')

    newkey = generate_key()
    if dryrun:
        print(f'Generated key, ignoring (dryrun)')
    else:
        with open(endpoint_privf, 'w') as keyf:
            keyf.write(keyexport(newkey))
            pass
        with open(endpoint_pubf, 'w') as keyf:
            keyf.write(keyexport(newkey.public_key))
            pass
        pass

    if dryrun:
        f = StringIO()
        save_endpoint_config(ep, f)
        f.seek(0)
        print("Dryrun Mode")
        print("===[snip]==")
        print(f.read())
        print("===[snip]==")
    else:
        logger.info(f'Save file {endpoint_file}')
        with open(endpoint_file, 'w') as cf:
            save_endpoint_config(ep, cf)

    # set hostname
    # public interface
    # trusted interfac
    # site key
    return 0

@app.command()
def publish(locus:           Annotated[str, t.Argument(help='short/familiar name, short hand for this mesh')],
            host_message:    Annotated[str, t.Argument(help='Host import string, or file with the message packet.')],
            config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
            force:           Annotated[bool,  t.Option(help='force overwrite')] = False,
            dryrun:          Annotated[bool,  t.Option(help='do not write anything')] = False,
            debug:           Annotated[bool,  t.Option(help='debug logging')] = False,
            trace:           Annotated[bool, t.Option(help='trace logging')] = False):
    ''' publish to dns '''
    LoggerConfig(debug, trace)
    print(f'{args} / {kwargs}')
    #uuid: 2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d
    #public_key: o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=
    #public_key_file: /etc/wireguard/x707_pub
    #private_key_file: /etc/wireguard/x707_priv
    #local_ipv4: oob.x707.ashbyte.com
    #local_ipv6: ''
    return 0

@app.command()
def list(ignore:          Annotated[str,  t.Option(help='Comma-delimited list of interfaces to ignore')] = '',
         config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
         debug:           Annotated[bool, t.Option(help='debug logging')] = False,
         trace:           Annotated[bool, t.Option(help='trace logging')] = False):
    ''' publish to dns '''
    LoggerConfig(debug, trace)

    import shutil

    skip_list = ignore.split(',')

    cmdfping = shutil.which('fping')
    if4, if6 = get_local_addresses_with_interfaces(skip_list)

    # report
    print("Located")
    print(f"  fping: {cmdfping}")
    print(f'  ipv4 addresses, by interface:{if4}')
    print(f'  ipv6 addresses, by interface:{if6}')

    for x in glob(f"{config_path}/*.yaml"):
        try:
            ep = load_endpoint_config(x)
        except:
            print(f"Not an endpoint / invalid endpoint: {x}")
            continue
        print(f"Found Endpoint: {x} / {ep.locus}")
        continue
    #uuid: 2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d
    #public_key: o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=
    #public_key_file: /etc/wireguard/x707_pub
    #private_key_file: /etc/wireguard/x707_priv
    #local_ipv4: oob.x707.ashbyte.com
    #local_ipv6: ''
    return 0

@app.command()
def deploy(*args, **kwargs):
    ''' do host-operations '''
    LoggerConfig(debug, trace)
    print(f'{args} / {kwargs}')
    return 0

if __name__ == "__main__":
    app()

