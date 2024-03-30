import pytest

from loguru import logger
from wgmesh.sitedata import Sitecfg, Host
from wgmesh.lib import asdict as wgmesh_asdict, LoggerConfig

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
        'asn_range': "64512:64525",
        'publickey': '',
        'privatekey': "site.key",
    }
}

host_data_blank = {
    'hostname': '',
    'asn': '',
    'octet': '',
    'local_ipv4': '',
    'local_ipv6': '',
    'public_key': '',
    'local_networks': '',
    'public_key_file': '',
    'private_key_file': '',
    'uuid': '',
}

host_data_test = {
    'hostname': 'remotetest.example.com',
    'asn': '0',
    'octet': '0',
    'local_ipv4': '',
    'local_ipv6': '',
    'public_key': '',
    'local_networks': '',
    'public_key_file': '',
    'private_key_file': '',
    'uuid': '7bc1bafe-87ba-4471-9ea7-6ef8e99b82c0',
}

def test_init():
    LoggerConfig(0, 0)
    pass

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
    s = Sitecfg(**test_data['global'])
    assert isinstance(s, Sitecfg)


def test_host_data():
    ''' validate that Sitecfg can generate an object '''
    s = Sitecfg(**test_data['global'])
    h = Host(sitecfg=s, **host_data_test)
    assert isinstance(h, Host)



#def test_endpoint_export():
#    ep = Endpoint(**test_data)
#    ep.openKeys()
#    data = wgmesh_asdict(ep)
#    with pytest.raises(Exception) as exc_info:   
#        data['_secret_key']
#    with pytest.raises(Exception) as exc_info:   
#        data['_public_key']
#
