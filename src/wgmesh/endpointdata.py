#!/usr/bin/env python3
''' endpoint data definition and validators '''

import attrs
import uuid
import socket

from loguru import logger
from nacl.public import PrivateKey, PublicKey
from attrs import define, validators, field, converters
from .crypto  import generate_key, load_public_key, load_secret_key

emptyValuesTuple = (None, '')

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg == None:
        return ''
    return arg

def convert_hostname(arg: str) -> str:
    if arg.strip() in emptyValuesTuple:
        return socket.gethostname()
    return arg

def convert_uuid(value):
    if value.strip() in emptyValuesTuple:
        return str( uuid.uuid4() )
    return value

@define
class Endpoint:
    hostname:               str = attrs.field(default='', converter=convert_hostname)
    uuid:                   str = attrs.field(default='', converter=convert_uuid)
    _secret_key:     PrivateKey = attrs.field(default='', )
    _public_key:      PublicKey = attrs.field(default='', )
    cmdfping:               str = field(default="/usr/sbin/fping", converter=str)
    secret_key_file:       str = field(default='', converter=nonone)
    public_key_file:        str = field(default='', converter=nonone)
    interface_public:       str = field(default='', converter=nonone)
    interface_trust:        str = field(default='', converter=nonone)
    interface_trust_ip:     str = field(default='', converter=nonone)
    interface_outbound:     str = field(default='', converter=nonone)
    
    def open_keys(self):
        ''' try to unpack the keys '''
        logger.trace('no open_keys')
        if self._secret_key in emptyValuesTuple:
            self._secret_key = load_secret_key(open(self.secret_key_file, 'r').read())
            self._public_key = self._secret_key.public_key
        elif self._public_keyfile not in emptyValuesTuple and self._public_key in emptyValuesTuple:
            self._public_key = load_public_key(open(self.public_key_file, 'r').read())
        else:
            raise ValueError('Key Already Exists')

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['_secret_key']
        del m2['_public_key']
        return m2
    pass

