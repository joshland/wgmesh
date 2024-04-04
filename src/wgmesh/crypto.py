#!/usr/bin/python3
""" this module handles all common crypto and key operations """

import base64
import binascii

from typing import Callable
from loguru import logger
from nacl.public import PrivateKey, PublicKey, Box

class InvalidPublicKey(Exception): pass
class InvalidSecretKey(Exception): pass

#warning: this function was never used. {???}
def decrypt(secret_key: PrivateKey, public_key: PublicKey, cipher_text: str|bytes) -> bytes:
    ''' encrypt a host blob target

    secret_key is either a UUEncoded Key or a realized PrivateKey
    public is either a UUEncoded Key or a realized PublicKey

    '''
    if not isinstance(secret_key, PrivateKey):
        raise InvalidSecretKey

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

def load_secret_key(key_string: str) -> PrivateKey:
    ''' read key from a key_string '''
    retval = loadkey(key_string, PrivateKey)
    validation_string = keyexport(retval)
    validation_string = 'x' * len(validation_string)
    logger.debug(f'Loaded Private{validation_string}/{len(validation_string)} bytes')
    return retval

def load_public_key(key_string: str) -> PublicKey:
    ''' read key from a key_string '''
    retval = loadkey(key_string, PublicKey)
    validation_string = keyexport(retval)
    logger.debug(f'Loaded Public: {validation_string}/{len(validation_string)} bytes')
    return retval

def loadkey(key_string: str, method: Callable[[str, Callable[[str], PublicKey | PrivateKey]], PrivateKey | PublicKey]) -> PrivateKey|PublicKey:
    ''' read key from a key_string '''
    pk = keyimport(key_string, method)
    return pk

def keyimport(key: str,  method: Callable[[str], PublicKey | PrivateKey]) -> PrivateKey|PublicKey:
    ''' uudecode a key '''
    logger.trace(f'keyimport: {type(key)}')
    if isinstance(key, bytes):
        key = key.decode()
    try:
        content = base64.b64decode(key)
    except binascii.Error as e:
        logger.error('Key is incorrectly padded.')
        logger.error(f'{key}')
        raise e
    logger.debug(f'Create KM Object key:{len(key)} / raw:{len(content)}')
    retval = method(content)
    return retval

def keyexport(key: PublicKey|PrivateKey) -> str:
    ''' encode a key '''
    logger.trace(f'keydecode: {type(key)}-{repr(key)}')
    retval = base64.b64encode(key.encode()).decode('utf-8')
    return retval

if __name__ == "__main__":
    ## Crypto library/encoding/decoding sanity check
    # make a priv key
    testkey = generate_key()
    # make a pub key
    pubkey = testkey.public_key
    # export the key
    public_export = keyexport(pubkey)
    secret_export = keyexport(testkey)
    public_export_bytes = public_export.encode('ascii')
    secret_export_bytes = secret_export.encode('ascii')
    # import the key
    public_import             = load_public_key(public_export)
    secret_import            = load_secret_key(secret_export)
    public_import_from_bytes  = load_public_key(public_export_bytes)
    secret_import_from_bytes = load_secret_key(secret_export_bytes)
    # *check kets
    assert pubkey == public_import == public_import_from_bytes      # validate the library can export/import public keys
    assert testkey == secret_import == secret_import_from_bytes    # validate that the library can export/import public keys
    assert pubkey == secret_import.public_key # validate that all the keys match

