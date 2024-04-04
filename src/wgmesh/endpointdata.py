#!/usr/bin/env python3
''' endpoint data definition and validators '''

import attrs
import uuid
import socket

from loguru import logger
from nacl.public import PrivateKey, PublicKey, Box
from attrs import define, validators, field, converters
from munch import munchify

from wgmesh.datalib import message_encode
from .crypto  import generate_key, keyexport, load_public_key, load_secret_key
from .datalib import asdict as wgmesh_asdict

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
    locus:                  str = field()
    site_domain:            str = field()
    site_pubkey:            str = field()
    hostname:               str = field(default='', converter=convert_hostname)
    uuid:                   str = field(default='', converter=convert_uuid)
    cmdfping:               str = field(default="/usr/sbin/fping", converter=str)
    secret_key_file:        str = field(default='', converter=nonone)
    public_key_file:        str = field(default='', converter=nonone)
    public_iface:           str = field(default='', converter=nonone)
    public_address:         str = field(default='', converter=nonone)
    trust_iface:            str = field(default='', converter=nonone)
    trust_address:          str = field(default='', converter=nonone)

    _site_key:        PublicKey = field(default='')
    _secret_key:     PrivateKey = field(default='')
    _public_key:      PublicKey = field(default='')
    
    def get_message_box(self, publickey: PublicKey) -> Box:
        ''' setup an SBox for decryption
        publickey: public key from the host who encrypted the message
        '''
        logger.trace(f"create encrypted with box {self.hostname} -> {publickey}")
        retval = Box(self._secret_key, publickey)
        return retval

    def get_public_key(self) -> str:
        return keyexport(self._public_key)

    def encrypt_message(self, message: str) -> str:
        ''' encrypt a message with the host public key for transmission or posting '''
        message_box = self.get_message_box(self._site_key)
        secure_message = message_box.encrypt( message.encode('ascii') )
        retval = message_encode(secure_message)
        return retval

    def export(self):
        ''' export local configuration for storage '''
        retval = wgmesh_asdict(self)
        return munchify(retval)

    def open_keys(self):
        ''' try to unpack the keys '''
        logger.trace('no open_keys')
        self._site_key = load_public_key(self.site_pubkey)
        if self._secret_key in emptyValuesTuple:
            self._secret_key = load_secret_key(open(self.secret_key_file, 'r').read())
            self._public_key = self._secret_key.public_key
        elif self._public_keyfile not in emptyValuesTuple and self._public_key in emptyValuesTuple:
            self._public_key = load_public_key(open(self.public_key_file, 'r').read())
        else:
            raise ValueError('Key Already Exists')

    def publish(self):
        ''' export local configuration for transport '''
        retval = {
            'hostname': self.hostname,
            'uuid': self.uuid,
            'public_key': self.get_public_key(),
            'public_key_file': self.public_key_file,
            'private_key_file': self.secret_key_file,
            'remote_addr': ",".join(self.public_address),
        }
        return munchify(retval)

