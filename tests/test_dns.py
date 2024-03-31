import pytest
import wgmesh
from wgmesh.lib import sort_and_join_encoded_data, dns_query, decode_domain, encode_domain, split_encoded_data, InvalidHostName
from loguru import logger

host_dns_response_encoded = [
    "1:qVy2ckAIwsO5lCm81DklL4LNEMjq0sjJrd3a5VSekf/2drtuW3J1i6q1cs4cYCLLdKmMoAIf/7CH",
    "2:Y4L1UvQmnB+63SXvgAZJzgiROki4QLI=",
    "0:mQxxMQrFwxwhR5Xbdlccp4siL5Qro6dxt8KWHIyeqT8OkI34yqFNFphh0ylFjDfNvG1ITyT5ikKa", ]

host_dns_response_decoded = 'mQxxMQrFwxwhR5Xbdlccp4siL5Qro6dxt8KWHIyeqT8OkI34yqFNFphh0ylFjDfNvG1ITyT5ikKaqVy2ckAIwsO5lCm81DklL4LNEMjq0sjJrd3a5VSekf/2drtuW3J1i6q1cs4cYCLLdKmMoAIf/7CHY4L1UvQmnB+63SXvgAZJzgiROki4QLI='

host_dns_query_test_record = 'fe0a8e93-5681-4e2b-b251-dd9cb6da1e8b.test.ashbyte.com'
host_dns_query_bad_record = 'badrecord.test.ashbyte.com'

fetch_domain_valid = 'mesh.ashbyte.com'
fetch_domain_invalid = 'badmesh.ashbyte.com'

decode_domain_payload_decoded = {'locus': 'test', 'publickey': 'O1wiV9r1DhBParqOUYBXD2OanH4X8TVcB75J/zi6LB0='}
decode_domain_payload_encoded = 'eyJsb2N1cyI6ICJ0ZXN0IiwgInB1YmxpY2tleSI6ICJPMXdpVjlyMURoQlBhcnFPVVlCWEQyT2FuSDRYOFRWY0I3NUovemk2TEIwPSJ9'

def test_split():
    retval = sort_and_join_encoded_data(host_dns_response_encoded)
    assert host_dns_response_decoded == retval

def test_dns_query():
    retval = dns_query(host_dns_query_test_record)
    assert retval == host_dns_response_decoded

def test_bad_dns_query():
    with pytest.raises(InvalidHostName) as exc_info:
        retval = dns_query(host_dns_query_bad_record)

''' fix this to use example.dyn.ashbyte.com '''
#def test_fetch_domain():
#    payload = dns_query(fetch_domain_valid)
#    mydomain = decode_domain(payload)
#    print(mydomain)

def test_decode_domain():
    payload = decode_domain(decode_domain_payload_encoded)
    assert payload == decode_domain_payload_decoded

def test_encode_domain():
    payload = encode_domain(decode_domain_payload_decoded)
    assert payload == decode_domain_payload_encoded

