#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
from json import JSONDecodeError
import os
import sys
import typer
from typing_extensions import Annotated

from loguru import logger

from wgmesh.lib import create_public_txt_record, domain_report, fetch_and_decode_record, load_site_config, message_decode
from wgmesh.lib import save_site_config, site_report, decode_domain, encode_domain, dns_query
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

    print("New mesh created")
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

    if locus[-4:] in ['yaml']:
        logger.warning("Removing '.yaml' from locus name.")
        locus = locus[:-5]
    config_file = os.path.join(config_path, f'{locus}.yaml')
    with open(config_file, 'r') as cf:
        site, hosts = load_site_config(cf)

    site_report(locus, site.publish())

    domain_report(site)

    # todo: check for Octet and ASN collisions

    # check for output
    # generate DNS payload, get public record
    # save records in [config_path]/dns_records file yaml
    # print results and changes


    return 0

@app.command()
def publish(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
            config_path:     Annotated[str, typer.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
            aws_zone:        Annotated[str, typer.Option(help='AWS Route53 Records Zone.')] = '',
            aws_access:      Annotated[str, typer.Option(envvar='AWS_ACCESS_KEY',help='AWS Access Key')] = '',
            aws_secret:      Annotated[str, typer.Option(envvar='AWS_SECRET_KEY',help='AWS Secret Key')] = '',
            force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
            dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
            debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
            trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    '''  publish to dns '''
    LoggerConfig(debug, trace)
    if dryrun:
        commit = False
    else:
        commit = True
    config_file = os.path.join(config_path, f'{locus}.yaml')

    if aws_zone:
        logger.warning(f'overriding DNS zone, forcing {aws_zone}')
        pass
    
    with open(config_file, 'r') as cf:
        site, hosts = load_site_config(cf)

    current_records = None
    try:
        current_records = fetch_and_decode_record(site.domain)
    except InvalidHostName:
        logger.debug(f'No records found for {site.domain}')
    except InvalidMessage:
        logger.warning(f'Invalid JSON Payload for {site.domain}') 

    public_message = site.publish_public_payload()

    if public_message == current_records:
        print("DNS Correct")
        if not force:
            site_report(locus, site.publish())
            domain_report(site)
            sys.exit(0)

    new_txt_record = create_public_txt_record(public_message)

    logger.info(f'Refreshing Records')
    r53con = Route53(site.route53, site.domain, 
                     aws_access_key=site.aws_access_key, aws_secret_access_key=site.aws_secret_access_key)

    r53con.save_txt_record(site.domain, new_txt_record, commit)

    for x in hosts:
        # list host
        # compile message
        # break into uuid.domain
        # base64 and save
        continue
    return 0

@app.command()
def host(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
         host_message:    Annotated[str, typer.Argument(help='Host import string, or file with the message packet.')],
         config_path:     Annotated[str, typer.Argument(envvar="WGM_CONFIG")] = '/etc/wireguard',
         force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
         dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
         debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
         trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    '''  do host-operations '''
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f'{locus}.yaml')
    
    with open(config_file) as cf:
        site, hosts = load_site_config

    if os.path.exists(host_message):
        with open(host_message, 'r') as msg:
            message = msg.read()
    else:
        message = host_message
        pass
    
    #outer_message = {'publickey': 'bas64 host key', 'message': 'encrypted_payload'}
    try:
        outer_message = json.loads(message_decode(message))
    except json.JSONDecodeError:
        bindec = message_decode(message)
        logger.debug(f'Invalid JSON Payload: {bindec}')
    except binascii.Error:
        logger.debug(f'Unexpected message, base64 decode failed {message}')
        pass

    hostkey = load_public_key(outer_message['publickey'])
    encypted_payload = message_decode(outer_message['message'])
    SBox = site.get_decryption_box(hostkey)

    hidden_message = SBox.decrypt(encrypted_payload)
    try:
        host_message = json.dumps(hidden_message)
    except JSONDecodeError:
        logger.error(f'Failed to decode the message from the host. {hidden_message}')
        pass

    host = Host(**host_message)
    # Load hosts
    # Match by UUID - that is the probable best approach
    # load into omage
    #encrypted_payload = {
    #    'uuid': '2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d',
    #    'public_key': 'o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=',
    #    'public_key_file': '/etc/wireguard/x707_pub',
    #    'private_key_file': '/etc/wireguard/x707_priv',
    #    'local_ipv4': 'oob.x707.ashbyte.com',
    #    'local_ipv6': '',
    #}

    return 0

if __name__ == "__main__":
    app()
