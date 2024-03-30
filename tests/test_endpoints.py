import pytest
import wgmesh
from wgmesh.endpointdata import Endpoint
from wgmesh.lib import asdict as wgmesh_asdict, LoggerConfig
from loguru import logger
from attrs import asdict

blank_data = {
    'hostname': '',
    'uuid': '',
    'secret_key': '',
    'public_key': '',
    'cmdfping': '',
    'secret_key_file': '',
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
    'secret_key_file': 'tests/test_priv',
    'public_key_file': 'tests/test_pub',
    'interface_public': '172.16.1.1',
    'interface_trust': 'ens0',
    'interface_trust_ip': '10.1.1.1',
    'interface_outbound': 'enp0s25',
}

def test_init():
    LoggerConfig(0, 0)
    pass

def test_endpoint_empty():
    ep = Endpoint()
    assert isinstance(ep, Endpoint)

def test_endpoint_blank():
    ep = Endpoint(**blank_data)
    assert isinstance(ep, Endpoint)

def test_endpoint():
    ep = Endpoint(**test_data)
    #[ assert v == test_data[k] for k, v in asdict(ep).items if k[0] != '_' ]
    for k, v in asdict(ep).items():
        if k[0] == "_": continue
        assert v == test_data[k]

def test_endpoint_keys():
    ep = Endpoint(**test_data)
    ep.open_keys()
    assert ep._public_key != ''
    assert ep._secret_key != ''

def test_endpoint_export():
    ep = Endpoint(**test_data)
    ep.open_keys()
    data = wgmesh_asdict(ep)
    with pytest.raises(Exception) as exc_info:   
        data['_secret_key']
    with pytest.raises(Exception) as exc_info:   
        data['_public_key']

