#!/usr/bin/env python3
''' lib.py - resource library for file and configuration operations '''

import sys
import json

from difflib import unified_diff
from typing import Callable, TextIO, List, Tuple

from loguru import logger
from ruamel.yaml import YAML
from natsort import natsorted
from munch import munchify, unmunchify

from .sitedata import Site, Sitecfg
from .endpointdata import Endpoint
from .datalib import message_encode, message_decode, dns_query, InvalidHostName

class InvalidMessage(Exception):
    ''' JSON document errors, or JSON decoding errors '''
    pass

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

def filediff(before, after, before_name, after_name):
    ''' perform a diff of two files '''
    diff = unified_diff(before.split('\n'), after.split('\n'), fromfile=before_name, tofile=after_name)
    return "\n".join([ x for x in diff if x.strip() > '' ])


def old_load_endpoint_config(source_file: TextIO, validate=True) -> Tuple[Endpoint]:
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

def old_save_endpoint_config(endpoint: Endpoint, dest_file: TextIO) -> bool:
    ''' load site config from disk

        fn: YAML file.
    '''
    yaml = YAML(typ='rt')

    output = {
        'local': unmunchify(endpoint.export())
    }

    yaml.dump(output, dest_file)
    return True

def create_public_txt_record(sitepayload: dict) -> List[str]:
    ''' encode and split the public record '''
    encoded_record = encode_domain(sitepayload)
    return encoded_record

def encode_domain(sitepayload: dict) -> str:
    ''' return the decoded domain package '''
    payload = json.dumps(sitepayload)
    retval = message_encode(payload)
    return retval

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
        logger.warning('DNS holds invalid data.')
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
    logger.trace(f"Site Report: {published_data}")
    data = munchify(published_data)
    print()
    print(f"Locus: {locus}")
    print(f"Domain: {data.domain}")
    print(f"ASN Range: {data.asn_range}")
    optprint(data.tunnel_ipv4, 'Tunel Routing(v4): %s')
    optprint(data.tunnel_ipv6, 'Tunel Routing(v6): %s')
    optprint(data.route53, 'AWS Route53 Zone: %s')
    if data.aws_credentials:
        optprint('present', 'Encrypted AWS Credentials: %s')
    else:
        optprint('*absent*', 'Encrypted AWS Credentials: %s')
