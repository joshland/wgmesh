#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
from logging import warning
import os
import sys
from io import StringIO
from glob import glob

import typer as t
from loguru import logger
from typing import Annotated
from munch import munchify, Munch, unmunchify
from ruamel.yaml import YAML

from .endpointdata import Endpoint
from .datalib import message_encode, message_decode, dns_query
from .datalib import fetch_and_decode_record
from .lib import LoggerConfig, filediff
from .version import VERSION
from .crypto import *
from .hostlib import get_local_addresses_with_interfaces

app = t.Typer()

def hostfile(locus: str, config_path:str) ->Munch:
    ''' common filename configuration '''
    retval = {
        'cfg_file': os.path.join(config_path, f'node_{locus}.yaml'),
        'sync_file': os.path.join(config_path, f'node_{locus}_siterecord.yaml'),
        'privkey': os.path.join(config_path, f'node_{locus}.key'),
        'pubkey': os.path.join(config_path, f'node_{locus}.pub'),
    }

    return munchify(retval)

def configure(filenames: dict,
              ep: Endpoint,
              hostname: str,
              trust_iface: str,
              trust_addrs: str,
              public_iface: str,
              public_addrs: str,
              asn:          int,
              dryrun: bool) -> Endpoint:
    ''' handle configuration '''
    old_data = ep.save_endpoint_config()

    if hostname:
        ep.hostname = hostname
    if trust_iface:
        ep.trust_iface = trust_iface
    if public_iface:
        ep.public_iface = public_iface
    if trust_addrs:
        ep.trust_address = trust_addrs.split(',')
    if public_addrs:
        ep.public_address = public_addrs.split(',')
    if public_addrs:
        ep.asn = asn

    new_data = ep.save_endpoint_config()
    diffdata = filediff(old_data, new_data, f'{filenames.cfg_file}.old', filenames.cfg_file)
    if dryrun:
        print(diffdata)
    else:
        logger.info(f'Save file {filenames.cfg_file}')
        print(diffdata)
        with open(filenames.cfg_file, 'w', encoding='utf-8') as cf:
            cf.write(new_data)
    return ep

@app.command()
def init(locus:           Annotated[str, t.Argument(help='Site locus')],
         domain:          Annotated[str, t.Argument(help='Locus domain name')],
         config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
         hostname:        Annotated[str, t.Option(help='Explicitly Set Hostname')] = None,
         trust_iface:     Annotated[str, t.Option(help='Trusted Interface')] = '',
         trust_addrs:     Annotated[str, t.Option(help='Trusted Addresses (delimit w/ comma')] = '',
         public_iface:    Annotated[str, t.Option(help='Public Interface')] = '',
         public_addrs:    Annotated[str, t.Option(help='Public Addresses (delimt w/ comma')] = False,
         asn:             Annotated[int, t.Option(help='ASN number')] = -1,
         force:           Annotated[bool, t.Option(help='force overwrite')] = False,
         dryrun:          Annotated[bool, t.Option(help='do not write anything')] = False,
         debug:           Annotated[bool, t.Option(help='debug logging')] = False,
         trace:           Annotated[bool, t.Option(help='trace logging')] = False):
    '''
    initial wgmesh site configuration, key generation and site buildout

    requires: locus and wgmesh
    '''
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)

    for x in (filenames.cfg_file, filenames.pubkey, filenames.privkey):
        if os.path.exists(x) and not (force or dryrun):
            logger.error(f"{x} exists, aborting (use --force to overwrite)")
            sys.exit(4)

    locus_info = fetch_and_decode_record(domain)
    if not locus_info:
        logger.error(f"Failed to fetch record, aborting")
        sys.exit(1)

    newkey = generate_key()
    if dryrun:
        print(f'Generated key, ignoring (dryrun)')
    else:
        with open(filenames.privkey, 'w', encoding='utf-8') as keyf:
            keyf.write(keyexport(newkey))
            pass
        with open(filenames.pubkey, 'w', encoding='utf-8') as keyf:
            keyf.write(keyexport(newkey.public_key))
            pass
        pass

    ep = Endpoint(locus, domain, locus_info['publickey'],
                  secret_key_file = filenames.privkey, public_key_file = filenames.pubkey)

    configure(filenames, ep, hostname,
              trust_iface, trust_addrs, public_iface, public_addrs, asn, dryrun)
    return 0

@app.command()
def config(locus:           Annotated[str, t.Argument(help='Site locus')],
           config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
           domain:          Annotated[str, t.Option(help='Locus domain name')] = None,
           hostname:        Annotated[str, t.Option(help='Explicitly Set Hostname')] = None,
           trust_iface:     Annotated[str, t.Option(help='Trusted Interface')] = '',
           trust_addrs:     Annotated[str, t.Option(help='Trusted Addresses (delimit w/ comma')] = '',
           public_iface:    Annotated[str, t.Option(help='Public Interface')] = '',
           public_addrs:    Annotated[str, t.Option(help='Public Addresses (delimt w/ comma')] = '',
           asn:             Annotated[int, t.Option(help='ASN number')] = -1,
           force:           Annotated[bool, t.Option(help='force overwrite')] = False,
           dryrun:          Annotated[bool, t.Option(help='do not write anything')] = False,
           debug:           Annotated[bool, t.Option(help='debug logging')] = False,
           trace:           Annotated[bool, t.Option(help='trace logging')] = False):
    ''' site (re)configuration '''
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)

    with open(filenames.cfg_file, 'r', encoding='utf-8') as cf:
        ep = Endpoint.load_endpoint_config(cf)

    if domain:
        if domain != ep.site_domain:
            logger.error(f'{domain} != {ep.site_domain}')
            logger.error('Changing the domain name is not supported at this time.')
            sys.exit(1)
        pass

    locus_info = fetch_and_decode_record(ep.site_domain)
    if not locus_info:
        logger.error(f"Failed to fetch record, aborting")
        sys.exit(1)

    configure(filenames, ep, hostname,
              trust_iface, trust_addrs, public_iface, public_addrs, asn, dryrun)

    return 0

@app.command()
def publish(locus:           Annotated[str, t.Argument(help='short/familiar name, short hand for this mesh')],
            config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
            outfile:         Annotated[str, t.Option(help='Output file')] = '',
            force:           Annotated[bool, t.Option(help='force overwrite')] = False,
            dryrun:          Annotated[bool, t.Option(help='do not write anything')] = False,
            debug:           Annotated[bool, t.Option(help='debug logging')] = False,
            trace:           Annotated[bool, t.Option(help='trace logging')] = False):
    ''' publish site registration - must be imported by wgsite master '''
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)
    with open(filenames.cfg_file, 'r', encoding='utf-8') as cf:
        ep = Endpoint.load_endpoint_config(cf)
        pass
    ep.open_keys()

    clear_payload = ep.publish().toJSON()
    logger.trace(f'Site Registration Package: {clear_payload}')
    b64_cipher_payload = ep.encrypt_message(clear_payload)

    logger.debug(f'Encrypted Package: {len(clear_payload)}/{len(b64_cipher_payload)}')
    logger.trace(f'Payload: {b64_cipher_payload}')

    host_package = munchify({'publickey': ep.public_key_encoded, 'message': b64_cipher_payload }).toJSON()
    host_message = message_encode(host_package)

    if outfile:
        if os.path.exists(outfile) and not force:
            print(f'Error: {outfile} exists, use --force to override')
            sys.exit(4)
        with open(outfile, 'w', encoding='utf-8') as mf:
            mf.write(host_message)
    else:
        print('Transmit the following b64 string, and use "wgsite host"')
        print(host_message)
        pass

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
    ''' list details about the host, current config(s), if any '''
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
            ep = Endpoint.load_endpoint_config(x)
        except:
            print(f"Not an endpoint / invalid endpoint: {x}")
            raise
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
def sync(locus:           Annotated[str, t.Argument(help='short/familiar name, short hand for this mesh')],
         config_path:     Annotated[str, t.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
         dryrun:          Annotated[bool, t.Option(help='do not write anything')] = False,
         debug:           Annotated[bool, t.Option(help='debug logging')] = False,
         trace:           Annotated[bool, t.Option(help='trace logging')] = False):
    ''' sync core changes from deployment-notices to local machine '''
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)
    with open(filenames.cfg_file, 'r', encoding='utf-8') as cf:
        ep = Endpoint.load_endpoint_config(cf)
        pass
    old_config = ep.save_endpoint_config()
    ep.open_keys()

    target = f'{str(ep.uuid)}.{ep.site_domain}'
    try:
        crypt = dns_query(target)
    except:
        logger.error(f"DNS Exception: {target}")
        print()
        sys.exit(1)
    sync_payload = munchify({}).fromJSON(ep.decrypt_message(crypt))
    yaml = YAML(typ='rt')
    if sync_payload.asn != ep.asn:
        logger.info(f'Update ASN from Site: {ep.asn} => {sync_payload.asn}')
        new_config = ep.save_endpoint_config()
    if dryrun:
        print('nothing saved')
        sys.exit(1)
    with open(filenames.sync_file, 'w') as sync_file:
       yaml.dump(unmunchify(sync_payload), sync_file)
    diffdata = filediff(old_config, new_config, f'{filenames.cfg_file}.old', filenames.cfg_file)
    print('Changeset:')
    print(diffdata)
    if sync_payload.asn != ep.asn:
        logger.info(f'Update ASN from Site: {ep.asn} => {sync_payload.asn}')
        with open(filenames.cfg_file, 'w', encoding='utf-8') as cf:
            cf.write(new_config)
    return 0

@app.command()
def deploy(*args, **kwargs):
    ''' deploy local wgmesh configuration and scripts '''
    LoggerConfig(debug, trace)
    print(f'{args} / {kwargs}')

    return 0

if __name__ == "__main__":
    app()

