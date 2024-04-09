#!/usr/bin/env python3
''' wgmesh site-specific operations '''

# Create the host basics locally
import os
import sys
import typer
from typing_extensions import Annotated

from loguru import logger
from munch import munchify, unmunchify, Munch

from .lib import create_public_txt_record, domain_report, fetch_and_decode_record
from .lib import site_report, decode_domain, encode_domain, dns_query, filediff
from .lib import InvalidHostName, InvalidMessage
from .lib import Sitecfg, LoggerConfig

from .transforms import SiteEncryptedHostRegistration

from .crypto import generate_site_key, load_secret_key, load_public_key, keyexport
from .route53 import Route53
from .sitedata import Host

app = typer.Typer()

@app.command()
def init(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
         domain:          Annotated[str, typer.Argument(help='primary domain where the locus TXT record will be published.')],
         asn:             Annotated[str, typer.Argument(help="Range of ASN Number (32bit ok) ex. 64512:64550")],
         config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
         secret_key_file: Annotated[str, typer.Option(help="secret key filename.")] = '',
         tunnel_ipv6:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
         tunnel_ipv4:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
         portbase:        Annotated[int, typer.Option(help="Starting Point for inter-system tunnel connections.")] = 0,
         aws_zone:        Annotated[str, typer.Option(help='AWS Route53 Records Zone.')] = '',
         aws_access:      Annotated[str, typer.Option(envvar='AWS_ACCESS_KEY',help='AWS Access Key')] = '',
         aws_secret:      Annotated[str, typer.Option(envvar='AWS_SECRET_KEY',help='AWS Secret Key')] = '',
         suggest:         Annotated[bool, typer.Option(help="Auto suggest tunnel networks")] = False,
         force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
         dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
         debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
         trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    '''
    generate initial host configuration

    requires: locus (matches familiar site),
              domainname (TXT record published by site master),
              ASN Range (BGP range for mesh instances)
    '''
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f'{locus}.yaml')

    if os.path.exists(config_file) and not force and not dryrun:
        logger.error(f'Error: {config_file} exists. Aborting. (use --force to overwrite)')
        sys.exit(1)

    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as cf:
            old_data = cf.read()
            pass
    else:
        old_data = ""
        pass

    if not secret_key_file:
        secret_path=os.path.join(config_path, f'{locus}_priv')
        logger.debug(f': {secret_key_file}')
    else:
        secret_path=secret_key_file
        pass
    if os.path.exists(secret_path):
        with open(secret_path, 'r', encoding='utf-8') as keyfile:
            secret_key = load_secret_key(keyfile.read())
    else:
        secret_key = generate_site_key(secret_path, dryrun)
        if dryrun:
            print(f'Generated key (discarding): {keyexport(secret_key)}')

    arguments = munchify({
        'locus': locus,
        'domain': domain,
        'asn_range': asn,
        'privatekey': secret_path
        })

    if tunnel_ipv6:
        arguments.tunnel_ipv6 = tunnel_ipv6
    elif suggest:
        arguments.tunnel_ipv6 = 'fd86:ea04:1116::/64'
        pass

    if tunnel_ipv4:
        arguments.tunnel_ipv4 = tunnel_ipv4
    elif suggest:
        arguments.tunnel_ipv4 = '192.0.2.0/24'
        pass

    if portbase:
        arguments.portbase = portbase
    elif suggest:
        arguments.portbase = 9000
        pass

    if aws_zone and aws_access and aws_secret:
        arguments.route53 = aws_zone
        arguments.aws_access_key = aws_access
        arguments.aws_secret_access_key = aws_secret
        pass

    site = Sitecfg(**arguments)
    site.open_keys()
    save_data = site.save_site_config()
    print(filediff(old_data, save_data, f"{config_file}.old", config_file))

    if dryrun:
        print("dryrun, no changes saved")
    else:
        with open(config_file, 'w', encoding='utf-8') as cf:
            cf.write(save_data)
            pass
        pass
    site_report(locus, site.publish())
    print("New mesh created")
    print(f"Now, you can run 'wgsite publish {site.locus}'")
    return 0

@app.command()
def check(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
          config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
          debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
          trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' check config, publish site report '''
    from io import StringIO

    LoggerConfig(debug, trace)

    if locus[-4:] in ['yaml']:
        logger.warning("Removing '.yaml' from locus name.")
        locus = locus[:-5]
    config_file = os.path.join(config_path, f'{locus}.yaml')
    with open(config_file, 'r', encoding='utf-8') as cf:
        site= Sitecfg.load_site_config(cf)

    site_report(locus, site.publish())

    domain_report(site)

    # todo: check for Octet and ASN collisions
    # check for output
    # generate DNS payload, get public record
    # save records in [config_path]/dns_records file yaml
    # print results and changes
    return 0

@app.command()
def config(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
           domain:          Annotated[str,
           typer.Argument(help='primary domain where the locus TXT record will be published.')] = '',
           asn:             Annotated[str, typer.Argument(help="Range of ASN Number (32bit ok) ex. 64512:64550")] = '',
           config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
           secret_key_file: Annotated[str, typer.Option(help="secret key filename.")] = '',
           tunnel_ipv6:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
           tunnel_ipv4:     Annotated[str, typer.Option(help="/64 ipv6 network block for tunnel routing")] = '',
           portbase:        Annotated[int, typer.Option(help="Starting Point for inter-system tunnel connections.")] = 0,
           aws_zone:        Annotated[str, typer.Option(help='AWS Route53 Records Zone.')] = '',
           aws_access:      Annotated[str, typer.Option(envvar='AWS_ACCESS_KEY',help='AWS Access Key')] = '',
           aws_secret:      Annotated[str, typer.Option(envvar='AWS_SECRET_KEY',help='AWS Secret Key')] = '',
           suggest:         Annotated[bool, typer.Option(help="Auto suggest tunnel networks")] = False,
           force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
           dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
           debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
           trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' (re)configure site settings '''
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f'{locus}.yaml')

    with open(config_file, 'r', encoding='utf-8') as cf:
        site= Sitecfg.load_site_config(cf)
        pass
    previous = site.save_site_config()

    update = ( 'asn','secret_key_file','tunnel_ipv6','tunnel_ipv4','portbase',)

    for x in update:
        val = locals().get(x)
        if val:
            site.__setattr__(x, val)
            continue
        continue

    if aws_zone and aws_access and aws_secret:
        arguments.route53 = aws_zone
        arguments.aws_access_key = aws_access
        arguments.aws_secret_access_key = aws_secret
        pass

    save_data = site.save_site_config()
    diff = filediff(previous, save_data, f"{config_file}.old", config_file)
    print(diff)

    site_report(locus, site.publish())
    with open(config_file, 'w', encoding='utf-8') as cf:
        cf.write(save_data)
    return 0

@app.command()
def genkeys(locus: Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
            config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
            force: Annotated[bool, typer.Option(help='overwrite existing key(s). NO TAKE BACKS')] = False):
    ''' generate new site key '''
    config_file = os.path.join(config_path, f'{locus}.yaml')
    with open(config_file, 'r', encoding='utf-8') as cf:
        site= Sitecfg.load_site_config(cf)
        pass
    if os.path.exists(site.privatekey) and not force:
        print(f'Key already exists: {site.privatekey}. Use --force to overwrite it.')
        sys.exit(4)

    key = generate_site_key(site.privatekey, False)

    print('Key overwritten, good luck')
    return 0

@app.command()
def publish(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
            config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
            aws_zone:        Annotated[str, typer.Option(help='AWS Route53 Records Zone.')] = '',
            aws_access:      Annotated[str, typer.Option(envvar='AWS_ACCESS_KEY',help='AWS Access Key')] = '',
            aws_secret:      Annotated[str, typer.Option(envvar='AWS_SECRET_KEY',help='AWS Secret Key')] = '',
            force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
            dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
            debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
            trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' publish site and host records to dns '''
    LoggerConfig(debug, trace)
    if dryrun:
        commit = False
    else:
        commit = True
    config_file = os.path.join(config_path, f'{locus}.yaml')

    if aws_zone:
        logger.warning(f'overriding DNS zone, forcing {aws_zone}')
        pass

    with open(config_file, 'r', encoding='utf-8') as cf:
        site = Sitecfg.load_site_config(cf)

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

    for host in hosts:
        dns_data = host.publish_peer_deploy()
        host.encrypt_message(dns_data)

    logger.error(f"Host publishing unwritten")
    print("warning: host publishing incomplete")
    #for me in hosts:
    #    docroot = me.publish_peer_deploy()
    #    docroot.hosts = []
    #    for h in hosts:
    #        if h.uuid == me.uuid:
    #            continue
    #        docroot.hosts.append(h.publish_peer_deploy())
    #        continue
    #    print(docroot)
    #    print(unmunchify(docroot))
    #    #generating host config

        #create host package
        # Create connection package for msh endpoints

        # list host
        # compile message
        # break into uuid.domain
        # base64 and save
     #   continue
    return 0

t = "\t"
@app.command()
def listhost(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
             uuid:            Annotated[str, typer.Argument(help='Host import string, or file with the message packet.')] = None,
             names:           Annotated[bool, typer.Option(help="Only list names and UUIDs")] = False,
             config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
             force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
             dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
             debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
             trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' Host import and update operations '''
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f'{locus}.yaml')

    with open(config_file, encoding='utf-8') as cf:
        site = Sitecfg.load_site_config(cf)
    if names:
        for x in site._hosts:
            print(f"{x.uuid}{t}{x.hostname}")
            continue
    else:
        for x in site._hosts:
            print(f'Host: {x.hostname}')
            print(f'UUID: {x.uuid}')
            print(f'ASN:{x.asn} Octet:=>[{site.portbase+x.octet}] [{x.octet}]')
            print(f'Address_v4:{x.local_ipv4}')
            print(f'Address_v6:{x.local_ipv6}')
            continue
    pass

@app.command()
def rmhost(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
           uuid:             Annotated[str, typer.Argument(help='Host import string, or file with the message packet.')],
           config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
           force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
           dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
           debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
           trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' Host import and update operations '''
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f'{locus}.yaml')

    with open(config_file, encoding='utf-8') as cf:
        site = Sitecfg.load_site_config(cf)

    old_data = site.save_site_config()
    site.host_delete(uuid)
    save_data = site.save_site_config()


    diff = filediff(old_data, save_data, f"{config_file}.old", config_file)
    print(diff)

    if dryrun:
        sys.exit(1)
    with open(config_file, 'w', encoding='utf-8') as cf:
        cf.write(save_data)
        pass
    return 0


@app.command()
def addhost(locus:           Annotated[str, typer.Argument(help='short/familiar name, short hand for this mesh')],
            host_message:    Annotated[str, typer.Argument(help='Host import string, or file with the message packet.')],
            config_path:     Annotated[str, typer.Option(envvar="WGM_CONFIG")] = '/etc/wireguard',
            force:           Annotated[bool, typer.Option(help='force overwrite')] = False,
            dryrun:          Annotated[bool, typer.Option(help='do not write anything')] = False,
            debug:           Annotated[bool, typer.Option(help='debug logging')] = False,
            trace:           Annotated[bool, typer.Option(help='trace logging')] = False):
    ''' Host import and update operations '''
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f'{locus}.yaml')

    with open(config_file, encoding='utf-8') as cf:
        site = Sitecfg.load_site_config(cf)

    old_data = site.save_site_config()
    if os.path.exists(host_message):
        logger.debug(f'{host_message} is a file.')
        with open(host_message, 'r', encoding='utf-8') as msg:
            message = msg.read()
    else:
        logger.debug(f'Message supplied through command line')
        message = host_message
        pass

    logger.debug(f'transform stage 1, decode')
    logger.trace(f'raw message: {message}')
    encrypted_record = SiteEncryptedHostRegistration.from_base64_json(message)
    logger.trace(f'(Decoded Message: {encrypted_record}')

    logger.debug(f'transform stage 2, decrypt')
    decryption_box = site.get_message_box(encrypted_record.publickey)
    host_record = encrypted_record.decrypt(decryption_box)
    logger.trace(f'decrypted host record: {host_record}')

    ## lookup existing, if it's an update
    host = site.get_host_by_uuid(host_record.uuid)
    if host:
        logger.debug(f'located existing host: {host}')
        pass

    # Compile to internal site document
    logger.debug(f'transform stage 4, Host Record: {host}')

    if host:
        logger.debug(f'Update host {host.uuid}/{host.hostname}')
        host.update(host)
    else:
        new_host = Host(sitecfg=site, **host_record)
        site.host_add(new_host)
        pass

    save_data = site.save_site_config()
    print(filediff(old_data, save_data, f"{config_file}.old", config_file))

    if dryrun:
        print("dryrun mode, no changes written")
    else:
        logger.trace(f'Save site: {site}')
        site_yaml = site.save_site_config()
        with open(config_file, 'w', encoding='utf-8') as cf:
            cf.write(site_yaml)

    #host = Host(**host_message)
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
