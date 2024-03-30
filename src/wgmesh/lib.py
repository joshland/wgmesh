#!/usr/bin/env python3
''' lib.py - resource library for file and configuration operations '''

import sys
import json
import base64

from io import StringIO
from typing import TextIO
from textwrap import wrap

from loguru import logger
from ruamel.yaml import YAML
from natsort import natsorted
import dns.resolver

#from .datalib import nonone
#from .endpointdata import Endpoint
from .sitedata import Sitecfg, Host

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

class StringYaml(YAML):
    def dumps(self, data, **kw):
        stream = StringIO()
        YAML.dump(self, data, stream, **kw)
        return stream.getvalue()

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

def save_site_config(site: Sitecfg, hosts: list, fn: TextIO):
    ''' commit config to disk

        site: Sitecfg
        hosts: List of Hosts
    '''
    sitedata = site.publish()
    dumphosts = { h.hostname: h.publish()[1] for h in hosts }
    publish = { 'global': sitedata,
                'hosts': dumphosts }

    yaml=StringYaml(typ='rt')

    yaml.dump(publish, fn)
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

def encode_domain(sitepayload: dict) -> str:
    ''' return the decoded domain package '''

    payload = json.dumps(sitepayload)
    retval = base64.b64encode(payload.encode('ascii')).decode('utf-8')
    return retval

def decode_domain(dnspayload: str) -> str:
    ''' return the decoded domain package '''

    text = base64.b64decode(dnspayload)#.encode('utf-8')
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

def optprint(arg, string):
    ''' optionally print a string if arg has a value '''
    if arg:
        if not isinstance(arg, str):
            arg = str(arg)
        print(string % arg)
        pass
    pass

def site_report(locus: str, published_data: dict) -> str:
    ''' compile a text report of the published site data '''
    from munch import munchify

    data = munchify(published_data)
    print()
    print("New mesh created")
    print(f"Locus: {locus}")
    print(f"Domain: {data.domain}")
    print(f"ASN Range: {data.asn_range}")
    optprint(data.tunnel_ipv4, 'Tunel Routing(v4): %s')
    optprint(data.tunnel_ipv6, 'Tunel Routing(v6): %s')
    optprint(data.route53, 'AWS Route53 Zone: %s')
    optprint(data.aws_access_key, 'AWS Route53 Access Cred: %s')
    optprint('x' * len(data.aws_secret_access_key), 'AWS Route53 Secret Cred: %s')


