from munch import unmunchify
import pytest
from uuid import UUID
from io import StringIO

from wgmesh.endpointdata import Endpoint
from wgmesh.datalib import asdict as wgmesh_asdict
from wgmesh.lib import LoggerConfig, load_endpoint_config
from loguru import logger
from attrs import asdict

blank_data = {
    'locus': '',
    'site_domain': '',
    'site_pubkey': '',
    'hostname': '',
    'uuid': '',
    'secret_key': '',
    'public_key': '',
    'cmdfping': '',
    'secret_key_file': '',
    'public_key_file': '',
    'public_iface': '',
    'public_address': '',
    'trust_iface': '',
    'trust_address': '',
    'asn': -1,
}

test_data = {
    'locus': 'test',
    'site_domain': 'test.example.com',
    'site_pubkey': '8BanecEAEKcByL4BDslkHNfPXiiljOgfd68g4A/cJlQ=',
    'hostname': 'customhost.ashbyte.com',
    'uuid': 'ee2c4908-03d1-44a8-b5d6-6f0fee981263',
    'cmdfping': '',
    'secret_key_file': 'tests/test_priv',
    'public_key_file': 'tests/test_pub',
    'public_iface': 'enp0s25',
    'public_address': '172.16.1.1',
    'trust_iface': 'ens0',
    'trust_address': '10.1.1.1',
    'asn': -1,
    'public_key': '',
}

ep_yaml_file = """
local:
  locus: test
  site_domain: test.example.com
  site_pubkey: 8BanecEAEKcByL4BDslkHNfPXiiljOgfd68g4A/cJlQ=
  hostname: customhost.ashbyte.com
  uuid: ee2c4908-03d1-44a8-b5d6-6f0fee981263
  cmdfping: ''
  secret_key_file: tests/test_priv
  public_key_file: tests/test_pub
  public_iface: enp0s25
  public_address: 172.16.1.1
  trust_iface: ens0
  trust_address: 10.1.1.1
  asn: -1
  public_key: ''
"""[1:]

def test_init():
    LoggerConfig(0, 0)
    pass

def test_endpoint_blank():
    ''' test loading an endpoint with a blank dataset '''
    ep = Endpoint(**blank_data)
    assert isinstance(ep, Endpoint)

def test_endpoint():
    ''' test endpoint with the test dataset '''
    ep = Endpoint(**test_data)
    for k, v in asdict(ep).items():
        if k[0] == "_": continue
        if isinstance(v, UUID):
            assert str(v) == test_data[k]
        else:
            assert v == test_data[k]
            continue
        continue

def test_endpoint_export():
    ''' test exporting the blank data set '''
    global output, ep
    ep = Endpoint(**test_data)
    output = unmunchify( ep.export() )
    assert output == test_data

def test_load_endpoint():
    ''' test endpoint loading functionality '''
    fn = StringIO()
    fn.write(ep_yaml_file)
    fn.seek(0)
    ep = load_endpoint_config(fn, validate=False)

def test_save_endpoint():
    ''' test saving the endpoint, test dataset '''
    ep = Endpoint(**test_data)
    output = ep.save_endpoint_config()
    assert output == ep_yaml_file

def test_endpoint_keys():
    ''' test the key storing and loading behavior '''
    ep = Endpoint(**test_data)
    ep.open_keys()
    assert ep.public_key != ''
    assert ep._secret_key != ''

def test_endpoint_export_empty():
    ''' test raw export behaviors, ensure that keys are not exported '''
    ep = Endpoint(**test_data)
    ep.open_keys()
    data = wgmesh_asdict(ep)
    with pytest.raises(Exception) as exc_info:
        data['_secret_key']
    with pytest.raises(Exception) as exc_info:
        data['_public_key']

