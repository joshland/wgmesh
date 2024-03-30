#!/usr/bin/env python3
''' lib.py - resource library for file and configuration operations '''
import os
import sys
import attrs
import typing

from io import StringIO
from loguru import logger
from ruamel.yaml import YAML

from .datalib import *
from .crypto import load_secret_key, load_public_key
from .endpointdata import Endpoint
from .sitedata import Sitecfg

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

def load_site_config(fn: str) -> tuple[Sitecfg, list]:
    ''' load site config from disk
        
        fn: YAML file.
    '''
    yaml = YAML(typ='rt')

    with open(fn) as yamlfile:
        y = yaml.load(yamlfile)
        pass

    logger.trace(f'Global: {y.get("global")}')
    logger.trace(f'Hosts: {y.get("hosts").keys()}')

    sitecfg = Sitecfg(**y.get('global', {}))
    sitecfg.open_keys()

    logger.trace(f'{sitecfg.MSK.public_key} /-/ {sitecfg.publickey}')

    hosts = []
    for k, v in y.get('hosts',{}).items():
        h = Host(k, sitecfg, **v)
        hosts.append(h)
        continue
    return sitecfg, hosts

def save_site_config(site: Sitecfg, hosts: list, fn: str):
    ''' commit config to disk

        site: Sitecfg
        hosts: List of Hosts
    '''
    sitedata = site.publish()
    dumphosts = { h.hostname: h.publish()[1] for h in hosts }
    publish = { 'global': sitedata,
                'hosts': dumphosts }

    yaml=StringYaml(typ='rt')

    if fn:
        logger.debug(f'Writing file: {fn}')
        with open(fn, 'w') as outfile:
            yaml.dump(publish, outfile)
    else:
        logger.info(f'Dumping to screen.')
        print(yaml.dumps(publish))
        pass
    return

