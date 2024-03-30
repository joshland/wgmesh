''' sited data definition and validator functions '''

import os
import ast
import uuid
from uuid import UUID
import ipaddress

from attr import asdict
from loguru import logger
from typing import Any
from attrs import define, validators, field
from nacl.public import PrivateKey, PublicKey
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from wgmesh.core import keyexport

from .crypto import load_secret_key, load_public_key
from .datalib import nonone
from .datalib import asdict as wgmesh_asdict

class HostMismatch(Exception): pass
class MissingAsnConfig(Exception): pass

def validateAsnRange(arg):
    ''' Check format, and expand the ASNs '''
    if arg == '':
        raise ValueError("site asn_range parameter missing")
    if isinstance(arg, (tuple, list)):
        retval = [ int(x) for x in arg ]
    else:
        logger.trace(f'trace: {arg}')
        try:
            low, high = [ int(x) for x in arg.split(':') ]
            retval = list(range(low, high + 1))
        except:
            retval = ast.literal_eval(arg)
        pass
    return retval

def convertNetworkAddress(arg):
    ''' validate and clean up network addressing '''
    logger.trace(f'convert network address: {arg}')
    retval = ipaddress.ip_network(arg)
    return retval

def convertIPAddress(arg):
    ''' validate and clean up network addressing '''
    if arg.strip() == '': return ''
    split = arg.split('/')
    logger.trace(f'convert network address: {split}')
    if split != '':
        retval = ipaddress.ip_address(split[0])
    else:
        logger.warning(f'Host with invalid ip address.')
        retval = ''
        pass
    return retval

def convertUUID(arg):
    ''' load UUID from site '''
    if arg.strip() == '':
        raise ValueError('empty string from host in invalid')
    retval = uuid.UUID(arg)
    return retval

@define
class Sitecfg:
    alerts: str = field(default='', validator=validators.instance_of(str))
    @alerts.validator
    def _check_alerts(self, attr, arg):
        ''' check for valid email address '''
        if not len(arg):
            return
        address, domain = arg.split('@')
        parts = domain.split('.')
        if len(parts) == 1:
            raise ValueError(f'{attr} address incorrect/incomplete: {arg}')
        return

    asn_range:  str|tuple|list = field(default='', converter=validateAsnRange)
    aws_access_key_id:     str = field(default='')
    aws_secret_access_key: str = field(default='')
    domain:                str = field(default='')
    locus:                 str = field(default='')
    tunnel_ipv4:   IPv4Network = field(default='192.168.12.0/24', converter=convertNetworkAddress)
    tunnel_ipv6:   IPv6Network = field(default='fd86:ea04:1116::/64', converter=convertNetworkAddress)
    portbase:              int = field(default = 58822, converter=int)
    publickey:             str = field(default='', converter=nonone)
    privatekey:            str = field(default='', converter=nonone)
    route53:               str = field(default='', converter=nonone)
    _master_site_key:PrivateKey|None = field(default='')

    def publish(self):
        ''' export local configuration for storage or transport '''
        retval = wgmesh_asdict(self)
        if isinstance(retval['publickey'], PublicKey):
            retval['publickey'] = keyexport(self.publickey)
        retval['tunnel_ipv4'] = str(self.tunnel_ipv4)
        retval['tunnel_ipv6'] = str(self.tunnel_ipv6)
        return retval

    def openKeys(self):
        ''' try to unpack the keys '''
        logger.trace('openKeys')

        if self._master_site_key:
            logger.error("Attempting to re-load the site key. Abort")
            sys.exit(2)

        if self.privatekey > '':
            if os.path.exists(self.privatekey):
                logger.trace(f'Open and read: {self.privatekey}')
                with open(self.privatekey, 'r') as keyfile:
                    self._master_site_key = load_secret_key(keyfile.read())
                    pass
                pass
        else:
            logger.error('Missing global->secret_key.  Run init?')
            sys.exit(3)

        if self.publickey:
            public_key = load_public_key(self.publickey)
            if public_key != self._master_site_key.public_key:
                logger.error(f'Public key in Site config does not match {self.privatekey}')
                sys.exit(1)
                pass
            logger.trace(f'Public key matches site key.')
            self.public_key = public_key
            pass
    pass

@define
class Host(object):
    hostname:             str = field()
    sitecfg:          Sitecfg = field()
    asn:                  int = field(default=0, converter=int)
    octet:                int = field(default=0, converter=int)
    local_ipv4:   IPv4Address = field(default='', converter=convertIPAddress)
    local_ipv6:   IPv6Address = field(default='', converter=convertIPAddress)
    public_key: PublicKey|str = field(default='')
    local_networks:       str = field(default = '')
    public_key_file:      str = field(default='')
    private_key_file:     str = field(default='')
    uuid:                UUID = field(default='', converter=convertUUID)

    def endport(self):
        ''' returns the octet added to the site.portbase '''
        retval = self.sitecfg.portbase + self.octet
        return retval

    def publish(self):
        retval = asdict(self)
        retval['local_ipv4'] = [ str(x) for x in self.local_ipv4 ]
        retval['local_ipv6'] = [ str(x) for x in self.local_ipv6 ]
        retval['publickey'] = keyexport(self.public_key)
        del retval['hostname']
        del retval['sitecfg']
        logger.trace(f'Host Pack: {retval}')
        return self.hostname, retval

    def update(self, host):
        ''' update host from a new record '''
        if self.uuid != host.uuid:
            raise HostMismatch

        hostname, hdict = host.publish()

        if self.hostname != hostname:
            self.info(f'Hostname Update: {self.hostname} => {hostname}')
            self.hostname = hostname
            pass

        for k, v in hdict.items():
            if k == 'asn': continue
            if k == 'octet': continue
            logger.trace(f'host update: {k}: {getattr(self, k)} => {v}')
            setattr(self, k, v)
            continue

        return True
    pass


