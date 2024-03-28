''' sited data definition and validator functions '''

import ast
import ipaddress
from ipaddress import IPv4Network, IPv6Network
from os import walk

from loguru import logger
from attrs import define, validators, field
from nacl.public import PrivateKey

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

def validateNetworkAddress(self, attr, arg):
    ''' validate and clean up network addressing '''
    logger.trace(f'convert network address: {arg}')
    retval = ipaddress.ip_network(arg)
    return retval

def validateIpAddress(self, attr, arg):
    ''' validate and clean up network addressing '''
    if arg.strip() == '': return ''
    split = arg.split('/')
    logger.trace(f'convert network address: {split[0]}')
    if split != '':
        retval = ipaddress.ip_address(split[0])
    else:
        logger.warning(f'Host with invalid ip address.')
        retval = ''
        pass
    return retval


@define
class Sitecfg:
    alerts: str = field(validator=validators.instance_of(str))
    @alerts.validator
    def _check_alerts(self, attr, arg):
        ''' check for valid email address '''
        if not len(value):
            return
        address, domain = arg.split('@')
        parts = domain.split('.')
        if len(parts) == 1:
            raise ValueError(f'{attr} address incorrect/incomplete: {arg}')
        return

    asn_range:  str|tuple|list = field(converter=validateAsnRange)
    aws_access_key_id:     str = field(validator=validators.instance_of(str))
    aws_secret_access_key: str = field(validator=validators.instance_of(str)) 
    domain:                str = field(validator=validators.instance_of(str)) 
    locus:                 str = field(validator=validators.instance_of(str)) 
    ipv4:          IPv4Network = field(default='192.168.12.0/24', converter=validateNetworkAddress)
    ipv6:          IPv6Network = field(default='fd86:ea04:1116::/64', converter=validateNetworkAddress)
    portbase:              int = field(default = 58822, converter=int)
    publickey:             str = field(default='', converter=nonone)
    privatekey:            str = field(default='', converter=nonone)
    route53:               str = field(default='', converter=nonone)
    master_site_key:PrivateKey = field(validator=validators.instance_of(PrivateKey))

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['MSK']
        del m2['ipv4']
        return m2
    pass



