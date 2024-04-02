import pytest

from loguru import logger
from wgmesh.sitedata import Sitecfg, Host, expandRange
from wgmesh.lib import LoggerConfig
#from wgmesh.datalib import asdict as wgmesh_asdict

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
        'privatekey': "site.key",
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

def test_init():
    LoggerConfig(1, 0)
    pass

def test_expandRange_single():
    values = expandRange("1")
    assert values == [1]

def test_expandRange_multiple():
    values = expandRange("1:3")
    assert values == [1, 2, 3]

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
    s = Sitecfg(**test_data['global']).publish()
    ## TODO: write a test to validate that the secret keyis not present
    ## write a test to validate the public key is encoded

def test_host_data():
    ''' validate that Sitecfg can generate an object '''
    logger.trace(f'host_data')
    s = Sitecfg(**test_data['global'])
    h = Host(sitecfg=s, **host_data_test)
    assert isinstance(h, Host)

#def test_endpoint_export():
#    ep = Endpoint(**test_data)
#    ep.open_keys()
#    data = wgmesh_asdict(ep)
#    with pytest.raises(Exception) as exc_info:   
#        data['_secret_key']
#    with pytest.raises(Exception) as exc_info:   
#        data['_public_key']
#
