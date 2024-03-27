import pytest
from nacl.public import PrivateKey, PublicKey, Box
from crypto import generate_key, keyexport, load_public_key, load_private_key 

def test_generate_key():
    testkey = generate_key()

    assert isinstance(testkey, PrivateKey)
    assert isinstance(testkey.public_key, PublicKey)

def test_keyexport():
    testkey = generate_key()
    private_export = keyexport(testkey)
    public_export = keyexport(testkey.public_key)

    assert isinstance(public_export, str)
    assert isinstance(private_export, str)

def test_loadkey():
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

if __name__ == "__main__":
    test_generate_key()
    test_keyexport()
    test_loadkey()
