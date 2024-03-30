#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
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

from wgmesh.lib import save_site_config
from .version import VERSION
from .route53 import Route53
from .crypto import *
from .lib import Sitecfg, LoggerConfig

app = typer.Typer()

def optprint(arg, string):
    ''' optionally print a string if arg has a value '''
    if arg:
        if not isinstance(arg, str):
            arg = str(arg)
        print(string % arg)
        pass
    pass

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
        arguments['aws_access_key_id'] = aws_access
        arguments['aws_secret_key_id'] = aws_secret
        pass

    site = Sitecfg(**arguments)
    if dryrun:
        save_site_config(site, [], '')
    else:
        site.openKeys()
        save_site_config(site, [], config_file)
        print()
        print("New mesh created")
        print(f"Locus: {locus}")
        print(f"Domain: {domain}")
        print(f"ASN Range: {asn}")
        optprint(site.tunnel_ipv4, 'Tunel Routing(v4): %s')
        optprint(site.tunnel_ipv6, 'Tunel Routing(v6): %s')
        optprint(aws_zone, 'AWS Route53 Zone: %s')
        optprint(aws_access, 'AWS Route53 Access Cred: %s')
        optprint('x' * len(aws_secret), 'AWS Route53 Secret Cred: %s')

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

