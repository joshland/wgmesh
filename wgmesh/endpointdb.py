import os
import re
import sys
import ast
import click
import base64
import loguru
import pprint
import socket
import ipaddress
import nacl.utils
import attr, inspect
import hashlib, uuid

import dns.resolver
from loguru import logger
from ruamel import yaml
from typing import Union
from nacl.public import PrivateKey, Box, PublicKey

from .core import loadkey, keyimport

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg == None:
        return ''
    return arg

def validateHostname(value):
    if value == None:
        return socket.gethostname()
    return value

def validateUuid(value):
    if value == None:
        return str( uuid.uuid4() )
    return value

@attr.s
class Endpoint(object):
    hostname = attr.ib(default=None, kw_only=True, converter=validateHostname)
    uuid     = attr.ib(default=None, kw_only=True, converter=validateUuid)
    SSK      = attr.ib(default='', kw_only=True)
    PPK      = attr.ib(default='', kw_only=True)
    private_key_file = attr.ib(default='', kw_only=True, converter=nonone)
    public_key_file  = attr.ib(default='', kw_only=True, converter=nonone)

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['SSK']
        del m2['PPK']
        return m2
    pass

@attr.s
class SiteDetail(object):
    locus      = attr.ib(default='', kw_only=True, converter=nonone)
    public_key = attr.ib(default='', kw_only=True, converter=nonone)
    PPK        = attr.ib(default='', kw_only=True)

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['PPK']
        return m2
    pass

class HostDB(object):
    def __init__(self, filename, **kwargs):
        self.filename = filename
        self.host  = Endpoint(**kwargs.get('host', {}))
        self.site  = SiteDetail(**kwargs.get('site', {}))
        pass

    def publish(self):
        retval = {
            'host': self.host.publish(),
            'site': self.site.publish(),
        }
        logger.trace(f'publish dict: {retval}')
        return retval
    pass

def load_host_config(domain: str, locus: str, pubkey: str) -> str:
    ''' Load/Generate local site-base config

    opens /etc/wireguard/{locus}.yaml

    return
    '''
    fn = f'/etc/wireguard/{domain}.yaml'

    try:
        with open(fn) as yamlfile:
            config = yaml.load(yamlfile, Loader=yaml.RoundTripLoader )
        baseconfig = False
    except FileNotFoundError:
        baseconfig = True
        config = {
            'site': {
                'locus': locus,
                'public_key': pubkey,
            },
        }
        pass

    retval = HostDB(fn, **config)

    return retval

def save_host_config(config: HostDB):
    ''' commit hostdb to disk '''
    filename = config.filename
    data = config.publish()
    ##leftoff - leave a way to update the file
    with open(filename, 'w') as yamlfile:
        yamlfile.write( yaml.dump(data, Dumper=yaml.RoundTripDumper) )
        pass

def CheckLostHostConfig(domain: str, locus: str, pubkey: str) -> str:
    ''' Load/Generate local site-base config

    Validate and update the settings.

    return
    '''
    config = load_host_config(domain, locus, pubkey)

    if config.host.private_key_file == '':
        config.host.private_key_file = f'/etc/wireguard/{locus}_priv'
        pass

    if config.host.public_key_file == '':
        config.host.public_key_file  = f'/etc/wireguard/{locus}_pub'
        pass

    try:
        SSK = loadkey(config.host.private_key_file, PrivateKey)
    except FileNotFoundError:
        logger.debug(f'Private key does not exist. {config.host.private_key_file}')
        SSK = None
        pass

    try:
        PPK = loadkey(config.host.public_key_file, PublicKey)
    except FileNotFoundError:
        logger.debug(f'Public key does not exist. {config.host.public_key_file}')
        PPK = None
        pass

    config.host.SSK = SSK
    config.host.PPK = PPK
    config.site.PPK = PublicKey(keyimport(config.site.public_key))

    save_host_config(config)

    return config

if __name__ == "__main__":
    from loguru import logger
    testkey = '2V4qw+wVPNlATGFE8DSc7S4FW+3p3AivgFBdQdKjkyY='
    hostdata = load_host_config('test.local.example', 'exampletest', testkey)
    save_host_config(hostdata)