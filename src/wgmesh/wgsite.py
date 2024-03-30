#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
from ast import Str
import os
import sys
from typing import Optional
from dns import wire
import typer
from typer.params import Option
from typing_extensions import Annotated
import base64
import binascii
import nacl.utils
import dns.resolver

from loguru import logger
from ruamel.yaml import YAML

from nacl.public import Box, PublicKey

from wgmesh.core import dns_query
from wgmesh.lib import load_site_config, save_site_config, site_report, decode_domain, encode_domain
from wgmesh.lib import InvalidHostName, InvalidMessage
from .version import VERSION
from .route53 import Route53
from .crypto import *
from .lib import Sitecfg, LoggerConfig

app = typer.Typer()

@app.command()
def init(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
         domain:          Annotated[str, typer.Argument(help='primary domain where the locus TXT record will be published.')],
         asn:             Annotated[str, typer.Argument(help="Range of ASN Number (32bit ok) ex. 64512:64550")],
         config_path:     Annotated[str, typer.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
         secret_key_file: Annotated[str, typer.Option(help="secret key filename.")] = '',
         tunnel_ipv6:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
         tunnel_ipv4:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
         portbase:        Annotated[int, typer.Option(help="Starting Point for inter-system tunnel connections.")] = 0,
         aws_zone:        Annotated[str, typer.Option(help='AWS Route53 Records Zone.')] = '',
         aws_access:      Annotated[str, typer.Option(envvar='AWS_ACCESS_KEY',help='AWS Access Key')] = '', 
         aws_secret:      Annotated[str, typer.Option(envvar='AWS_SECRET_KEY',help='AWS Secret Key')] = '', 
         force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
         dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
         debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
         trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' 
    do site init stuff 
    '''
    LoggerConfig(debug, trace)

    config_file = os.path.join(config_path, f'{locus}.yaml')
    
    if os.path.exists(config_file) and not force and not dryrun:
        logger.error(f'Error: {config_file} exists.  Aborting. (use --force to overwrite)')
        sys.exit(1)

    if not secret_key_file:
        secret_path=os.path.join(config_path, f'{locus}_priv')
        logger.debug(f': {secret_key_file}')
    else:
        secret_path=secret_key_file
        pass
    if os.path.exists(secret_path):
        with open(secret_path, 'r') as keyfile:
            secret_key = load_secret_key(keyfile.read())
    else:
        secret_key = generate_key()
        if dryrun:
            print(f'Generated key (discarding): {keyexport(secret_key)}')
        else:
            with open(secret_path, 'w') as keyfile:
                keyfile.write(keyexport(secret_key))
                pass
            pass
        pass

    arguments = {
        'locus': locus,
        'domain': domain,
        'asn_range': asn,
        'privatekey': secret_path
        }

    if tunnel_ipv6: arguments['tunnel_ipv6'] = tunnel_ipv6
    if tunnel_ipv4: arguments['tunnel_ipv4'] = tunnel_ipv4
    if portbase: arguments['portbase'] = portbase
    if aws_zone and aws_access and aws_secret:
        arguments['route53'] = aws_zone
        arguments['aws_access_key'] = aws_access
        arguments['aws_secret_access_key'] = aws_secret
        pass

    site = Sitecfg(**arguments)
    if dryrun:
        from io import StringIO
        buf = StringIO()
        save_site_config(site, [], buf)
        buf.seek(0)
        print(buf.read())
    else:
        site.open_keys()
        with open(config_file, 'w') as cf:
            save_site_config(site, [], cf)
            pass
        report = site.publish()

        site_report(locus, report)
    return 0

@app.command()
def check(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
          config_path:     Annotated[str, typer.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
          secret_key_file: Annotated[str, typer.Option(help="secret key filename.")] = '',
          tunnel_ipv6:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
          tunnel_ipv4:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
          portbase:        Annotated[int, typer.Option(help="Starting Point for inter-system tunnel connections.")] = 0,
          aws_zone:        Annotated[str, typer.Option(help='AWS Route53 Records Zone.')] = '',
          aws_access:      Annotated[str, typer.Option(envvar='AWS_ACCESS_KEY',help='AWS Access Key')] = '', 
          aws_secret:      Annotated[str, typer.Option(envvar='AWS_SECRET_KEY',help='AWS Secret Key')] = '', 
          force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
          dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
          debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
          trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' check the config '''
    from io import StringIO

    LoggerConfig(debug, trace)

    config_file = os.path.join(config_path, f'{locus}.yaml')
    with open(config_file, 'r') as cf:
        site, hosts = load_site_config(cf)

    site_report(locus, site.publish())

    try:
        published_data = dns_query(site.domain)
    except InvalidHostName:
        published_data = None

    try:
        if published_data:
            existing_records = decode_domain(published_data)
    except InvalidMessage:
        logger.warning(f'DNS holds invalid data.')
        existing_records = None

    dns_payload = site.publish_public_payload()

    print()
    if existing_records:
        if existing_records == dns_payload:
            print("DNS CHECK: Passed")
        else:
            print("DNS CHECK: Failed")
        print(f"  - Calculated: {dns_payload}")
        print(f"  - Published: {existing_records}")

    # todo: check for Octet and ASN collisions

    # check for output
    # generate DNS payload, get public record
    # save records in [config_path]/dns_records file yaml
    # print results and changes


    return 0

@app.command()
def publish(*args, **kwargs):
    ''' 
    publish to dns 
    '''
    print(f'{args} / {kwargs}')
    return 0

@app.command()
def host(*args, **kwargs):
    ''' 
    do host-operations
    '''
    print(f'{args} / {kwargs}')
    return 0

if __name__ == "__main__":
    app()

