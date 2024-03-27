#!/usr/bin/python3
""" this module handles all common crypto and key operations """

import base64
import binascii

from typing import Callable
from loguru import logger
from nacl.public import PrivateKey, PublicKey, Box

class InvalidPublicKey(Exception): pass
class InvalidPrivateKey(Exception): pass

#warning: this function was never used. {???}
def decrypt(secret_key: PrivateKey, public_key: PublicKey, cipher_text: str|bytes) -> bytes:
    ''' encrypt a host blob target

    secret_key is either a UUEncoded Key or a realized PrivateKey
    public is either a UUEncoded Key or a realized PublicKey

    '''
    if not isinstance(secret_key, PrivateKey):
        raise InvalidPrivateKey
    
    if not isinstance(public_key, PublicKey):
        raise InvalidPublicKey

    if isinstance(cipher_text, str):
        logger.trace(f'convert cipher_text[str] to ASCII.')
        cipher_text = cipher_text.encode('ascii')
        pass

    try:
        cipher_text = base64.decodebytes(cipher_text)
    except binascii.Error:
        logger.trace(f'cipher_text appears to be raw')

    sBox = Box(secret_key, public_key)
    payload = sBox.decrypt(cipher_text)
    return payload

def generate_key() -> PrivateKey:
    ''' generate a key '''
    retval = PrivateKey.generate()
    return retval

def load_private_key(key_string: str|bytes) -> PrivateKey:
    ''' read key from a key_string '''
    return loadkey(key_string, PrivateKey)

def load_public_key(key_string: str|bytes) -> PublicKey:
    ''' read key from a key_string '''
    return loadkey(key_string, PublicKey)

def loadkey(key_string: str|bytes, method: Callable) -> PrivateKey|PublicKey:
    ''' read key from a key_string '''
    pk = keyimport(key_string, method)
    assert isinstance(pk, (PublicKey, PrivateKey))
    return pk

def keyimport(key: str|bytes,  method: Callable) -> PrivateKey|PublicKey:
    ''' uudecode a key '''
    logger.trace(f'keyimport: {type(key)}-{repr(key)}')
    if isinstance(key, bytes):
        key = key.decode()
    try:
        content = base64.decodebytes(key.encode('ascii')).strip()
        logger.trace(f'{len(content)}:{repr(content)} // {len(key)}:{repr(key)}')
    except binascii.Error:
        logger.debug(r'base64 decode fails - assume raw key.')
        content = key.encode('ascii')
        pass
    logger.debug(f'Create KM Object key:{len(key)} / raw:{len(content)}')
    pk = method(content)
    validation_string = keyexport(pk)
    if isinstance(pk, PrivateKey):
        validation_string = 'x' * len(validation_string)
        key_type = 'Private'
    else:
        key_type = "Public"
    logger.debug(f'Encoded {key_type}: {validation_string}/{len(validation_string)} bytes')

    assert isinstance(pk, (PublicKey, PrivateKey))
    return pk

def keyexport(key: PublicKey|PrivateKey) -> str:
    ''' encode a key '''
    logger.trace(f'keydecode: {type(key)}-{repr(key)}')
    retval = base64.encodebytes(key.encode()).decode().strip()
    return retval


if __name__ == "__main__":
    ## Crypto library/encoding/decoding sanity check
    # make a priv key
    testkey = generate_key()
    # make a pub key
    pubkey = testkey.public_key
    # export the key
    public_export = keyexport(pubkey)
    private_export = keyexport(testkey)
    public_export_bytes = public_export.encode('ascii')
    private_export_bytes = private_export.encode('ascii')
    # import the key
    public_import             = load_public_key(public_export)
    private_import            = load_private_key(private_export)
    public_import_from_bytes  = load_public_key(public_export_bytes)
    private_import_from_bytes = load_private_key(private_export_bytes)
    # *check kets
    assert pubkey == public_import == public_import_from_bytes      # validate the library can export/import public keys
    assert testkey == private_import == private_import_from_bytes    # validate that the library can export/import public keys
    assert pubkey == private_import.public_key # validate that all the keys match

