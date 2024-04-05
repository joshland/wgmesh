import pytest

from base64 import b64encode, b64decode

from attr import asdict
from munch import munchify, unmunchify
from nacl.public import PrivateKey, PublicKey, Box

from wgmesh.lib import LoggerConfig
from wgmesh.transforms import SiteEncryptedHostRegistration, SitePublicRecord

LoggerConfig(1,0)

message = munchify({'publickey': 'demokey', 'message': 'simulatedb64'})

json_message = message.toJSON()

base64_message_bytes = b64encode(json_message.encode('ascii'))

base64_message_str = base64_message_bytes.decode('utf-8')


def test_encryptedhostregistration():
    sehr = SiteEncryptedHostRegistration.from_base64_json(base64_message_str)
    assert list(asdict(sehr).keys()) == ['publickey', 'message']
