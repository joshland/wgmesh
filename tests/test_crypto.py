import pytest

from nacl.public import PrivateKey, PublicKey, Box
from wgmesh.lib import LoggerConfig
from wgmesh.crypto import generate_key, keyimport, keyexport, load_public_key, load_secret_key

test_key_secret = 'OSm+bnxiopuxZU75TDaCF4mOOlZDBw11KrDDGshol9A='
test_key_public = '8BanecEAEKcByL4BDslkHNfPXiiljOgfd68g4A/cJlQ='

def test_init():
    LoggerConfig(False, False)

def test_generate_key():
    ''' verify that generate_key produces valid keys '''
    testkey = generate_key()

    assert isinstance(testkey, PrivateKey)
    assert isinstance(testkey.public_key, PublicKey)

def test_keyexport():
    ''' verify that keyexport produces strings '''
    testkey = generate_key()
    private_export = keyexport(testkey)
    public_export = keyexport(testkey.public_key)

    assert isinstance(public_export, str)
    assert isinstance(private_export, str)

def test_local_keys():
    ''' test theprocess of importing and exporting the keys '''
    sk = load_secret_key(test_key_secret)
    pk = load_public_key(test_key_public)
    export_sk = keyexport(sk)
    export_pk = keyexport(pk)
    export_sk_pk = keyexport(sk.public_key)
    assert test_key_secret == export_sk
    assert test_key_public == export_pk == export_sk_pk

def test_throw_key_padding_exception():
    import binascii

    with pytest.raises(binascii.Error):
        keyimport('alkjasdlfkjasdlkj', PrivateKey)

def test_keyexport_loadkey_integration():
    ''' integration test to validate that keys can be exported and imported '''
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
    private_import            = load_secret_key(private_export)
    public_import_from_bytes  = load_public_key(public_export_bytes)
    private_import_from_bytes = load_secret_key(private_export_bytes)
    # *check kets
    assert pubkey == public_import == public_import_from_bytes      # validate the library can export/import public keys
    assert testkey == private_import == private_import_from_bytes    # validate that the library can export/import public keys
    assert pubkey == private_import.public_key # validate that all the keys match

if __name__ == "__main__":
    test_generate_key()
    test_keyexport()
    test_keyexport_loadkey_integration()
