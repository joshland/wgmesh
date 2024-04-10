import pytest

from loguru import logger
from munch import munchify
from ipaddress import IPv4Address, IPv6Address
from wgmesh.crypto import load_public_key
from wgmesh.sitedata import Sitecfg, Host, expandRange, collapse_asn_list
from wgmesh.lib import LoggerConfig
from wgmesh.transforms import SitePublicRecord

blank_data = {
    'global': {
        'alerts': "",
        'domain': "",
        'tunnel_ipv4': "",
        'tunnel_ipv6': "",
        'locus': "",
        'portbase': 21100,
        'asn_range': "",
        'publickey': '',
        'privatekey': "",
    }
}

test_data = {
    'global': {
        'alerts': "alerts@example.com",
        'domain': "example.com",
        'tunnel_ipv4': "172.16.42.0/24",
        'tunnel_ipv6': "fd86:ea04:1116::/64",
        # Examples: https://simpledns.plus/private-ipv6
        'locus': "wgmesh",
        'portbase': 21100,
        'asn_range': '64512:64520,65100,65120:65125',
        'publickey': '',
        'privatekey': "tests/test_priv",
    }
}

test_contrained_data = {
    'global': {
        'alerts': "alerts@example.com",
        'domain': "example.com",
        'tunnel_ipv4': "172.16.42.0/24",
        'tunnel_ipv6': "fd86:ea04:1116::/64",
        # Examples: https://simpledns.plus/private-ipv6
        'locus': "wgmesh",
        'portbase': 21100,
        'asn_range': '64512:64513',
        'publickey': '',
        'privatekey': "tests/test_priv",
    }
}

host_data_blank = {
    'hostname': '',
    'asn': '-1',
    'octet': '-1',
    'local_ipv4': '',
    'local_ipv6': [],
    'public_key': '',
    'local_networks': '',
    'public_key_file': '',
    'private_key_file': '',
    'uuid': '',
}

host_data_test = {
    'hostname': 'remotetest.example.com',
    'asn': -1,
    'octet': -1,
    'local_ipv4': [],
    'local_ipv6': [],
    'public_key': '',
    'local_networks': '',
    'public_key_file': '',
    'private_key_file': '',
    'uuid': '7bc1bafe-87ba-4471-9ea7-6ef8e99b82c0',
}

host_yaml_raw_data = """
global:
  alerts: ''
  asn_range: 4200000000:4200000010,4200000015
  asn_used:
  - 4200000000
  aws_access_key:
  aws_secret_access_key:
  domain: example.dyn.ashbyte.com
  locus: example
  tunnel_ipv4: 100.0.0.0/24
  tunnel_ipv6: fd7b:c042:23c5:a33f::/64
  portbase: 7000
  publickey: bVEY8bpWDjKY/K7w1u3i+noShGhRHfFpzPEb1hebBAE=
  privatekey: dev/example_priv
  route53: Z1WPZU95RUKGNI
hosts:
  aee8a79f-c608-4fe9-8484-cdef6911366f:
    uuid: aee8a79f-c608-4fe9-8484-cdef6911366f
    hostname: AtomBattler.ashbyte.com
    asn: 4200000000
    octet: 1
    local_ipv4:
    - 4.2.2.2/32
    - 8.8.8.8/32
    - fd86:ea04:1116::1/128
    local_ipv6: []
    public_key: ''
    local_networks: ''
    public_key_file: dev/example_endpoint_pub
    private_key_file: dev/example_endpoint_priv
"""[1:]

host_add_test_data0 = {
        'uuid': '36d6d7fc-9157-4ab8-8d0b-cb1298b8aaec',
        'hostname': 'wgtest01.ashbyte.com',
        'asn': -1,
        'public_key': '',
        'public_key_file': '/home/joshua/_git/wgmesh/tests/wgtest01/example_endpoint_pub',
        'private_key_file': '/home/joshua/_git/wgmesh/tests/wgtest01/example_endpoint_priv',
        'local_ipv4': [IPv4Address('192.0.2.1')],
        'local_ipv6': [IPv6Address('fd86:ea04:1116:1::1')]
}

host_add_test_data1 = {
        'uuid': '7ff9fb7c-53d7-4e64-b298-1bc89998c1c',
        'hostname': 'wgtest02.ashbyte.com',
        'asn': -1,
        'public_key': '',
        'public_key_file': '/home/joshua/_git/wgmesh/tests/wgtest02/example_endpoint_pub',
        'private_key_file': '/home/joshua/_git/wgmesh/tests/wgtest02/example_endpoint_priv',
        'local_ipv4': [IPv4Address('192.0.3.1')],
        'local_ipv6': [IPv6Address('fd86:ea04:1116:2::1')],
}

with open('tests/test_pub', 'r') as pubf:
    test_public_key_encoded = pubf.read()
    test_public_key_decoded = load_public_key(test_public_key_encoded)

with open('tests/test_priv', 'r') as prvf:
   test_private_key_encoded = prvf.read()
   test_private_key_decoded = load_public_key(test_private_key_encoded)

spr_integration_payload = {'locus': 'example', 'publickey': test_public_key_encoded }

test_collapse_expanded_list = [ 22, 23, 24, 25, 1, 2, 3, 4, 10, 11, 12, 13 ]
test_collapse_collapsed_list = "1:4,10:13,22:25"

def test_init():
    LoggerConfig(True, True)
    pass

def test_expandRange_single():
    values = expandRange("1")
    assert values == [1]

def test_expandRange_multiple():
    values = expandRange("1:3")
    assert values == [1, 2, 3]

def test_collapse_list():
    values = collapse_asn_list(test_collapse_expanded_list)
    assert test_collapse_collapsed_list == values

def test_site_emtpy():
    ''' validate that Sitecfg will fail on required fields '''
    with pytest.raises(ValueError) as exc_info:
        s = Sitecfg()

def test_site_blank():
    ''' validate that Sitecfg can generate an object '''
    with pytest.raises(ValueError) as exc_info:
        s = Sitecfg(**blank_data['global'])

def test_site_testdata():
    ''' validate that Sitecfg can generate an object '''
    logger.trace(f'testdata')
    s = Sitecfg(**test_data['global'])
    assert isinstance(s, Sitecfg)

def test_site_publish():
    ''' validate that Sitecfg can generate an object '''
    logger.trace(f'site_publish')
    s = Sitecfg(**test_data['global'])
    s.open_keys()
    s = s.publish()
    print(s)

    with pytest.raises(AttributeError) as exc_info:
        k = s._privatekey

    with pytest.raises(AttributeError) as exc_info:
        k = s._private_key
    ## TODO: write a test to validate that the secret keyis not present
    ## write a test to validate the public key is encoded

def test_site_public_record():
    spr = SitePublicRecord('example', test_public_key_encoded)
    export = spr.publish()
    assert tuple(export.keys()) == ('locus', 'publickey')

def test_site_loaddata():
    site = Sitecfg.load_site_config(host_yaml_raw_data)
    save_data = site.save_site_config()
    spr = Sitecfg.load_site_config(save_data)
    assert isinstance(spr, Sitecfg)

def test_spr_integration_test():
    jsonpayload = munchify(spr_integration_payload).toJSON()
    spr = SitePublicRecord.fromJSON(jsonpayload)
    export = spr.publish()
    assert tuple(export.keys()) == ('locus', 'publickey')

def test_site_host_integration():
    ''' validate that Sitecfg can generate an object '''
    s = Sitecfg(**test_data['global'])
    h = Host(sitecfg=s, **host_data_test)
    assert isinstance(h, Host)

def test_site_host_integration_save():
    ''' validate that Sitecfg can generate an object '''
    s = Sitecfg(**test_data['global'])
    h = Host(sitecfg=s, **host_data_test)
    yaml_data = s.save_site_config()

def test_site_add_host():
    ''' test adding a host to a site '''
    s = Sitecfg(**test_contrained_data['global'])
    h = Host(sitecfg=s, **host_add_test_data0)
    with pytest.raises(ValueError) as exc:
        h2 = Host(sitecfg=s, **host_add_test_data1)

#def test_endpoint_export():
#    ep = Endpoint(**test_data)
#    ep.open_keys()
#    data = wgmesh_asdict(ep)
#    with pytest.raises(Exception) as exc_info:
#        data['_secret_key']
#    with pytest.raises(Exception) as exc_info:
#        data['_public_key']
#
