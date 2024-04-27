from munch import munchify, unmunchify
import pytest
from uuid import UUID
from io import StringIO

from wgmesh.crypto import keyexport
from wgmesh.endpointdata import Endpoint
from wgmesh.datalib import asdict as wgmesh_asdict
from wgmesh.lib import LoggerConfig
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
    'public_key_encoded': '8BanecEAEKcByL4BDslkHNfPXiiljOgfd68g4A/cJlQ=',
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
  public_key_encoded: 8BanecEAEKcByL4BDslkHNfPXiiljOgfd68g4A/cJlQ=
"""[1:]

LoggerConfig(True, True)

def test_endpoint_blank():
    ''' test loading an endpoint with a blank dataset '''
    ep = Endpoint(**blank_data)
    assert isinstance(ep, Endpoint)

def test_endpoint():
    ''' test endpoint with the test dataset '''
    ep = Endpoint(**test_data)
    logger.trace(ep)
    compare = munchify(test_data)
    logger.trace(compare)
    export_dict = munchify(asdict(ep))
    logger.trace(export_dict)
    assert compare.locus == export_dict.locus
    assert compare.site_domain == export_dict.site_domain
    assert compare.site_pubkey == export_dict.site_pubkey
    assert compare.hostname == export_dict.hostname
    assert compare.uuid == str(export_dict.uuid)
    assert compare.public_key_encoded == export_dict.public_key_encoded
    assert compare.cmdfping == export_dict.cmdfping
    assert compare.secret_key_file == export_dict.secret_key_file
    assert compare.public_key_file == export_dict.public_key_file
    assert compare.public_iface == export_dict.public_iface
    assert compare.public_address == export_dict.public_address
    assert compare.trust_iface == export_dict.trust_iface
    assert compare.trust_address == export_dict.trust_address
    assert compare.asn == export_dict.asn

def test_endpoint_export():
    ''' test exporting the blank data set '''
    ep = Endpoint(**test_data)
    output = unmunchify( ep.export() )
    assert output == test_data

def test_load_endpoint():
    ''' test endpoint loading functionality '''
    fn = StringIO()
    fn.write(ep_yaml_file)
    fn.seek(0)
    ep = Endpoint.load_endpoint_config(fn, validate=False)

def test_save_endpoint():
    ''' test saving the endpoint, test dataset '''
    ep = Endpoint(**test_data)
    output = ep.save_endpoint_config()
    assert output == ep_yaml_file

def test_save_endpoint_keys():
    ''' test saving the endpoint, test dataset '''
    ep = Endpoint(**test_data)
    ep.open_keys()
    output = ep.save_endpoint_config()
    assert output == ep_yaml_file

def test_endpoint_keys():
    ''' test the key storing and loading behavior '''
    global ep

    ep = Endpoint(**test_data)
    ep.open_keys()
    assert ep.public_key_encoded != ''
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

