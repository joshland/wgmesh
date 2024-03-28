import pytest
import wgmesh
from wgmesh.endpointdata import Endpoint
from loguru import logger
from attrs import asdict

blank_data = {
    'hostname': '',
    'uuid': '',
    'secret_key': '',
    'public_key': '',
    'cmdfping': '',
    'private_key_file': '',
    'public_key_file': '',
    'interface_public': '',
    'interface_trust': '',
    'interface_trust_ip': '',
    'interface_outbound': '',
}

test_data = {
    'hostname': 'customhost.ashbyte.com',
    'uuid': 'ee2c4908-03d1-44a8-b5d6-6f0fee981263',
    'secret_key': '',
    'public_key': '',
    'cmdfping': '',
    'private_key_file': 'tests/test_priv',
    'public_key_file': 'tests/test_pub',
    'interface_public': '172.16.1.1',
    'interface_trust': 'ens0',
    'interface_trust_ip': '10.1.1.1',
    'interface_outbound': 'enp0s25',
}

def test_endpoint_empty():
    ep = Endpoint()
    logger.info(ep)
    assert isinstance(ep, Endpoint)

def test_endpoint_blank():
    ep = Endpoint(**blank_data)
    logger.info(ep)
    assert isinstance(ep, Endpoint)

def test_endpoint():
    ep = Endpoint(**test_data)
    logger.info(ep)
    for k, v in asdict(ep).items():
        assert v == test_data[k]

def test_endpoint_keys():
    ep = Endpoint(**test_data)
    ep.openKeys()
    logger.info(ep)
    assert ep.public_key != ''
    assert ep.secret_key != ''
