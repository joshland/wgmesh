#!/usr/bin/env python3

from base64 import b64encode, b64decode
import base64
from munch import munchify, unmunchify
from nacl.public import Box, PublicKey, PrivateKey
from attr import define, field, asdict
from loguru import logger

from .crypto import keyexport

##
## Document transformations
##

##
# Transformations:
#
# disk -> memory
# site -> &hosts
# memory -> disk
# hosts &-> Site -> YAML
#
# site -> public DNS
# 2
#

def convert_public_key(arg):
    ''' convert a public key to base64 encoded '''
    ## fixme: this is backwards
    if isinstance(arg, PublicKey):
        return keyexport(arg)
    else:
        return arg

def convert_list_to_csv(arg):
    ''' join a list with comma's '''
    return ','.join(arg)

def convert_base64_to_bytes(arg):
    ''' convert a binary payload to binary '''
    return base64.b64decode(arg)

@define
class SitePublicRecord:
    locus: str = field()
    publickey: PublicKey = field(converter=convert_public_key)
    def toJSON(self):
        return munchify(asdict(self)).toJSON()
    def publish(self):
        return munchify(asdict(self))
    @classmethod
    def fromJSON(cls, jsonstring):
        ''' load the json string '''
        values = munchify({}).fromJSON(jsonstring)
        spr = cls(values.locus, values.publickey)
        return spr

@define
class SiteEncryptedHostRegistration:
    publickey: PublicKey = field(converter=convert_public_key)
    message:       bytes = field(converter=convert_base64_to_bytes)
    @classmethod
    def from_base64_json(cls, payload):
        ''' decode a base64 message, and return the Encrypted Message '''
        raw_message = base64.b64decode(payload).decode('utf-8')
        content = munchify({}).fromJSON(raw_message)
        return SiteEncryptedHostRegistration(content.publickey, content.message)
    def decrypt(self, box: Box):
        ''' attempt to decrypt the message '''
        hidden_message = box.decyrpt(self.message)
        logger.trace(f'Decrypted message: {hidden_message}')
        retval = HostRegistration(hidden_message.uuid,
                                  hidden_message.public_key,
                                  hidden_message.public_key_file,)
        retval.split_remotes(hidden_message.remote_addr)
        return retval

@define
class HostRegistration:
    uuid:             str = field(converter=str)
    public_key:       str = field()
    public_key_file:  str = field()
    private_key_file: str = field()
    local_ipv4:       str = field(converter=convert_list_to_csv, default=[])
    local_ipv6:       str = field(converter=convert_list_to_csv, default=[])
    def split_remotes(self, remote_addrs):
        ''' older host registrations send all remote addresses in a single list '''
        for x in remote_addrs.split(','):
            try:
                addr = ip_address(x)
            except ValueError:
                logger.warning(f'Ignoring invalid IP: {x}')
                continue
            if addr.version == 4:
                self.local_ipv4.append(addr)
                logger.trace(f': Host remote address: {addr}')
            elif addr.version == 6:
                self.local_ipv6.append(addr)
                logger.trace(f': Host remote address: {addr}')
            else:
                logger.error(f'Unknown Address: x')
                continue
            continue



@define
class EncryptedHostRegistration:
    publickey: PublicKey = field()
    privatekey: PrivateKey = field()

    def publish(self):
        ''' render the total payload for host registration '''
        return {}


#
# public dns -> host
# host -> site message

#
# site -> host configuration
#

#
# host -> deployment templating
#



