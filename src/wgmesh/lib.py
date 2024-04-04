#!/usr/bin/env python3
''' lib.py - resource library for file and configuration operations '''

from logging import warning
import sys
import json
import base64

from io import StringIO
from typing import TextIO, List, Tuple
from textwrap import wrap
from munch import munchify, unmunchify

import dns.resolver
from loguru import logger
from netaddr import expand_partial_ipv4_address
from ruamel.yaml import YAML
from natsort import natsorted
from munch import munchify

from .sitedata import Sitecfg, Host
from .endpointdata import Endpoint
from .datalib import message_encode, message_decode

class InvalidHostName(Exception): pass
class InvalidMessage(Exception): pass

def LoggerConfig(debug: bool, trace: bool):
    '''
    Setup logging configuration.
    '''
    if not debug and not trace:
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        pass

    if debug:
        logger.info('Debug')
        logger.remove()
        logger.add(sys.stdout, level='DEBUG')
        pass

    if trace:
        logger.info('Trace')
        logger.remove()
        logger.add(sys.stdout, level='TRACE')
        pass

    pass

def load_endpoint_config(source_file: TextIO, validate=True) -> Tuple[Endpoint]:
    ''' load site config from disk

        fn: YAML file.
    '''
    yaml = YAML(typ='rt')

    y = yaml.load(source_file)
    logger.trace(f'Local: {y.get("local")}')
    ep_values = munchify(y.get('local'))

    if validate:
        site_dict = {'locus': ep_values.locus, 'publickey': ep_values.site_pubkey }
        public_records = fetch_and_decode_record(ep_values.site_domain)
        if public_records != site_dict:
            logger.error(f"Locus Mismatch: {y['host']['domain']}")
            logger.error(f"Config: {y['site']}")
            logger.error(f"DNS: {public_records}")
            pass

    retval = Endpoint(**ep_values)
    return retval

def save_endpoint_config(endpoint: Endpoint, dest_file: TextIO) -> bool:
    ''' load site config from disk

        fn: YAML file.
    '''
    yaml = YAML(typ='rt')

    output = {
        'local': unmunchify(endpoint.export())
    }

    yaml.dump(output, dest_file)
    return True

def load_site_config(source_file: TextIO) -> tuple[Sitecfg, list]:
    ''' load site config from disk

        fn: YAML file.
    '''
    yaml = YAML(typ='rt')

    y = yaml.load(source_file)

    logger.trace(f'Global: {y.get("global")}')
    logger.trace(f'Hosts: {y.get("hosts").keys()}')

    sitecfg = Sitecfg(**y.get('global', {}))
    sitecfg.open_keys()

    logger.trace(f'{sitecfg._master_site_key.public_key} /-/ {sitecfg.publickey}')

    hosts = []
    for k, v in y.get('hosts',{}).items():
        h = Host(k, sitecfg, **v)
        hosts.append(h)
        continue
    return sitecfg, hosts

def save_site_config(site: Sitecfg, hosts: list, dest_file: TextIO):
    ''' commit config to disk

        site: Sitecfg
        hosts: List of Hosts
    '''
    yaml = YAML(typ='rt')

    sitedata = site.publish()
    dumphosts = { h.hostname: h.publish()[1] for h in hosts }
    publish = { 'global': unmunchify(sitedata),
                'hosts': unmunchify(dumphosts) }

    yaml.dump(publish, dest_file)
    return

def sort_and_join_encoded_data(data):
    ''' take incoming encoded text, look for split order markers '''
    if data[0].find(':') > -1:
        logger.trace(f'Ordered DNS List Published: {data}')
        slist = []
        for r in data:
            if not r or r.strip() == '': continue
            k, v = r.split(':')
            slist.append((k, v))
            continue
        sortlist = natsorted(slist)
        retval = "".join([ x[1] for x in sortlist ])
    else:
        logger.trace('Unordered DNS List Published.')
        retval = "".join(data)
        pass

    return retval

def split_encoded_data(data):
    ''' split base64 encoded string to a 76-character line length '''
    retval = [ f'{i}:{x}' for i, x in enumerate(wrap(data, width=74)) if x > '' ]
    return retval

def dns_query(domain: str) -> str:
    ''' return the record from the DNS '''
    try:
        answer = dns.resolver.resolve(domain,"TXT").response.answer[0]
    except dns.resolver.NXDOMAIN as exc:
        logger.error(f"Invalid Hostname {domain} / No TXT Record.")
        raise InvalidHostName from exc

    response = []
    for item in answer:
        logger.trace(f'{item} // {type(item)}')
        item = str(item).replace(' ', '\n').replace('"', '')
        response += item.split('\n')
        continue

    retval = sort_and_join_encoded_data(response)
    logger.trace(f'Avengers Assembled: {retval}')
    return retval

def create_public_txt_record(sitepayload: dict) -> List[str]:
    ''' encode and split the public record '''
    encoded_record = encode_domain(sitepayload)
    txt_record = split_encoded_data(encoded_record)
    return txt_record

def encode_domain(sitepayload: dict) -> str:
   ''' return the decoded domain package '''
   payload = json.dumps(sitepayload)
   retval = message_encode(payload)
   return retval

def decode_domain(dnspayload: str) -> str:
    ''' return the decoded domain package '''
    text = message_decode(dnspayload)
    logger.trace(f'Output: {text} // {type(text)}')
    try:
        retval = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.debug(f'Invalid JSON payload from DNS: {text}')
        raise InvalidMessage from exc
    for k, v in retval.items():
        if isinstance(v, bytes):
            retval[k] = v.decode()
            continue
        continue
    return retval

def fetch_and_decode_record(domain_name: str) -> dict:
    dns_data = dns_query(domain_name)
    decoded_data = decode_domain(sort_and_join_encoded_data(dns_data))
    return decoded_data

def optprint(arg, string):
    ''' optionally print a string if arg has a value '''
    if arg:
        if not isinstance(arg, str):
            arg = str(arg)
        print(string % arg)
        pass
    pass

def domain_report(site: Sitecfg) -> bool:
    ''' publish dns_report '''

    try:
        published_data = dns_query(site.domain)
    except InvalidHostName:
        published_data = None

    existing_records = None
    try:
        if published_data:
            existing_records = decode_domain(published_data)
    except InvalidMessage:
        logger.warning(f'DNS holds invalid data.')
        existing_records = "[Invalid data]"

    dns_payload = site.publish_public_payload()

    print()
    if existing_records:
        if existing_records == dns_payload:
            print("DNS CHECK: Passed")
        else:
            print("DNS CHECK: Failed")
        print(f"  - Calculated: {dns_payload}")
        print(f"  - Published: {existing_records}")

    return True


def site_report(locus: str, published_data: dict) -> str:
    ''' compile a text report of the published site data '''
    from munch import munchify

    data = munchify(published_data)
    print()
    print(f"Locus: {locus}")
    print(f"Domain: {data.domain}")
    print(f"ASN Range: {data.asn_range}")
    optprint(data.tunnel_ipv4, 'Tunel Routing(v4): %s')
    optprint(data.tunnel_ipv6, 'Tunel Routing(v6): %s')
    optprint(data.route53, 'AWS Route53 Zone: %s')
    optprint(data.aws_access_key, 'AWS Route53 Access Cred: %s')
    optprint('x' * len(data.aws_secret_access_key), 'AWS Route53 Secret Cred: %s')


