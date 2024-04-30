#!/usr/bin/python3
""" this module handles all common crypto and key operations """

import base64
import binascii

from typing import Callable, Union
from loguru import logger

from nacl.public import PrivateKey, PublicKey, Box

class InvalidPublicKey(Exception):
    ''' raised when an incorrect or empty is key is passed to a crypto function '''
    pass
class InvalidSecretKey(Exception):
    ''' raised when an incorrect or empty is key is passed to a crypto function '''
    pass

#warning: this function was never used. {???}
def decrypt(secret_key: PrivateKey, public_key: PublicKey, cipher_text: Union[str,bytes]) -> bytes:
    ''' encrypt a host blob target

    secret_key is either a UUEncoded Key or a realized PrivateKey
    public is either a UUEncoded Key or a realized PublicKey

    '''
    if not isinstance(secret_key, PrivateKey):
        raise InvalidSecretKey

    if not isinstance(public_key, PublicKey):
        raise InvalidPublicKey

    if isinstance(cipher_text, str):
        logger.trace('convert cipher_text[str] to ASCII.')
        cipher_text = cipher_text.encode('ascii')
        pass

    try:
        cipher_text = base64.decodebytes(cipher_text)
    except binascii.Error:
        logger.trace('cipher_text appears to be raw')

    sBox = Box(secret_key, public_key)
    payload = sBox.decrypt(cipher_text)
    return payload

def generate_key() -> PrivateKey:
    ''' generate a key '''
    retval = PrivateKey.generate()
    return retval

def generate_site_key(secret_path: str, dryrun: bool) -> PrivateKey:
    ''' generate and store keys '''
    newkey = generate_key()
    if dryrun:
        return newkey
    with open(secret_path, 'w', encoding='utf-8') as keyfile:
        keyfile.write(keyexport(newkey))
        pass
    return newkey

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

def loadkey(key_string: str, method: Callable[[str, Callable[[str], Union[PublicKey, PrivateKey]]], Union[PrivateKey,PublicKey]]) -> Union[PrivateKey,PublicKey]:
    ''' read key from a key_string '''
    pk = keyimport(key_string, method)
    return pk

def keyimport(key: str, method: Callable[[str], Union[PublicKey, PrivateKey]]) -> Union[PrivateKey, PublicKey]:
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

def keyexport(key: Union[PublicKey,PrivateKey]) -> str:
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

    message = "nhvoNFM/DrMKgvRDSb7ii1SP8xbPoDThHzzMA17Vk8FKFedmgnaKI14FFIwuh7R9oRD6BpC3IAvJmV5oULE3/ieK0UOp0EOx5JxwUFQy+DQQUkj8pM1Equ4xXEd3yrjHn63CAx/gYgOf5iA83WZq7pUOAtqY/xVvpJd1juv3cvPByghLd/IKna29tEo4xkBNCc0THorx63xlhp8MNVLbS0mntQqHScT1GQMjrNL48Sc5aOCuMBjLrtAZN9pwajA9TgSqTkwhvOus7uk0RtMvYkZ24Lrqe+UArpEqpwVWMYWgx+WELrUjOaKqM+g8mUqMQV9I07ZScjPbZOtoNkRB8l4JrAWVF1Dc8iu8cgvI1+IBBnPFk/SpDJzxWnsOBp43aUqVDrBp7eyo/AK3/xrtJQeCvSHuMG5/Jma1gB1ZAoU99rJv3r99FN2NNVU020vctPhDCgg+fjXNbWzzb6b6EhTvWL8x0+ZTmCvkhUS8imNYnwxFj+Sjebj3PNnP+EtpGIklwX6NLZeOy1RxRbdryjzblUZnl6UNV29LpiSfBXkN6fg1G43ZQDbHNaZEbUlmWVGN47w+fnP1B4Kx9vDf1is86VC3BHlpvgIHc93mKKcEeng3+YERwO0VSPfILbTIhdfk0eTWNpDduTo0r0M8d/dUbngsH+MIa30HIObB3/mpOltfhtrXIqiONrqJEjnpI6531rcVfCegRNLw+CBwdxDbbeDXdAniHAuJEdWj7M51V7E1oLIMoxw7wEoONBo8ck3fNMDoGlEVAkhs/LA8gT3hekCK+FcjnG8aZVtXL81O7SAk8nL78PBHseh4gRGwcBmtEKv/QUFi9BXvwJfmPo2NyTfugSSgnaBO643F02kjUDWrXIDrEU02TnslxvaaCcFOW2ZxDQ2S0yJCF843//dvU2Ti5yjo6X1eNW3aanNhlfCuhjHAQg+P3SCGOjFYBTsQugGOgh7L3mrOixF4DAYbTRFdULI7AcVFPqQxN26kjHvlUp+geXwHYbWlph113i0EFleyAECmY8TWqrpvNIMhAqyITrF9Udo/rf+N6ztTRVM2l7YROiQ/nzpXcShWo7E67gMRHDcrZZ6dtS/fStA0v3uRc7kqq/DbyuoKsqebxDDOmSKxBfeSx8zN1AVsesgLbU2ZRwvzGy2DUuynqFOiZTwLORw="
    site_pub = "bVEY8bpWDjKY/K7w1u3i+noShGhRHfFpzPEb1hebBAE="
    node_key = "/Txyv8HEBIaiTXlVWcNIY2FHDI8rwS5EstGBk9Po8B8=%"
    spkey = load_public_key(site_pub)
    nskey = load_secret_key(node_key)
    retval = decrypt(nskey, spkey, message)
    print(retval)
