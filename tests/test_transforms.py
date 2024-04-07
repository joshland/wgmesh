import pytest

from base64 import b64encode, b64decode

from attr import asdict
from munch import munchify, unmunchify
from nacl.public import PrivateKey, PublicKey, Box

from wgmesh.lib import LoggerConfig
from wgmesh.crypto import generate_key
from wgmesh.transforms import EncryptedHostRegistration, SiteEncryptedHostRegistration, SitePublicRecord, EncryptedAWSSecrets

LoggerConfig(1,0)

message = munchify({'publickey': 'demokey', 'message': 'simulatedb64'})
json_message = message.toJSON()
base64_message_bytes = b64encode(json_message.encode('ascii'))
base64_message_str = base64_message_bytes.decode('utf-8')

raw_aws_credentials = {'access_key': 'access_test_key', 'secret_key': 'secret_test_key' }
aws_secrets = EncryptedAWSSecrets(**raw_aws_credentials)
aws_test_key = generate_key()


def test_encryptedhostregistration():
    sehr = SiteEncryptedHostRegistration.from_base64_json(base64_message_str)
    assert list(asdict(sehr).keys()) == ['publickey', 'message']

def test_encryptedawssecrets_integration():
    ## simulate encryption
    box = Box(aws_test_key, aws_test_key.public_key)
    stored_credentials = aws_secrets.export_encrypted_credentials(box)
    ## simulate decryption
    box = Box(aws_test_key, aws_test_key.public_key)
    restored_credentials = EncryptedAWSSecrets.load_encrypted_credentials(stored_credentials, box)

    assert restored_credentials == aws_secrets

