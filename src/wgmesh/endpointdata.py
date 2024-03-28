#!/usr/bin/env python3
''' endpoint data definition and validators '''

import attrs
import uuid
import socket

from loguru import logger
from nacl.public import PrivateKey, PublicKey
from attrs import define, validators, field, converters
from .crypto  import generate_key, load_public_key, load_private_key

emptyValuesTuple = (None, '')

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg == None:
        return ''
    return arg

def convert_hostname(arg: str) -> str:
    print(arg)
    logger.trace(f'hostname: {arg}')
    if arg.strip() in emptyValuesTuple:
        return socket.gethostname()
    return arg

def convert_uuid(value):
    print(value)
    logger.trace(f'uuid: {value}')
    if value.strip() in emptyValuesTuple:
        return str( uuid.uuid4() )
    return value

#def convert_private_key(arg):
#    ''' use a key, or make a new one '''
#    logger.trace(f'{arg}')
#
#    if arg.strip() == '': 
#        return ''
#    try:
#        retval = load_private_key(arg)
#    except:
#        raise ValueError("invalid private key")
#    return retval
#
#def convert_public_key(arg):
#    ''' use a key, or make a new one '''
#    logger.trace(f'{arg}')
#    if arg.strip() == '': 
#        return ''
#    try:
#        retval = load_public_key(arg)
#    except:
#        raise ValueError("invalid public key")
#    return retval

@define
class Endpoint:
    hostname:               str = attrs.field(default='', converter=convert_hostname)
    uuid:                   str = attrs.field(default='', converter=convert_uuid)
    secret_key:      PrivateKey = attrs.field(default='')
    public_key:       PublicKey = attrs.field(default='')
    cmdfping:               str = field(default="/usr/sbin/fping", converter=str)
    private_key_file:       str = field(default='', converter=nonone)
    public_key_file:        str = field(default='', converter=nonone)
    interface_public:       str = field(default='', converter=nonone)
    interface_trust:        str = field(default='', converter=nonone)
    interface_trust_ip:     str = field(default='', converter=nonone)
    interface_outbound:     str = field(default='', converter=nonone)
    
    def openKeys(self):
        ''' try to unpack the keys '''
        logger.trace('no openKeys')
        if self.secret_key in emptyValuesTuple:
            self.secret_key = load_private_key(open(self.private_key_file, 'r').read())
            self.public_key = self.secret_key.public_key
        elif self.public_keyfile not in emptyValuesTuple and self.public_key in emptyValuesTuple:
            self.public_key = load_public_key(open(self.public_key_file, 'r').read())
        else:
            raise ValueError('Key Already Exists')

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['secret_key']
        del m2['public_key']
        return m2
    pass

