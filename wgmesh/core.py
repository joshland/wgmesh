#!/usr/bin/env python3

##
## wgcore.py
##

# Handle basic operations of loading and saving YAML files.
# Basic Objects for managing site-specific and location specific settings.
import os
import re
import sys
import ast
import click
import base64
import ifaddr
import pprint
import ipaddress
import dns.resolver
import attr

from io import StringIO
from typing import Union
from ruamel.yaml import YAML
from loguru import logger
from natsort import natsorted
from nacl.public import PrivateKey, Box, PublicKey

from .version import VERSION

class HostMismatch(Exception): pass

## Validators must be loaded first
def validateNetworkAddress(arg):
    ''' validate and clean up network addressing '''
    logger.trace(f'convert network address: {arg}')
    retval = ipaddress.ip_network(arg)
    return retval

def validateLocalAddresses(arg):
    ''' validate and clean up network addressing '''
    retval = []
    if isinstance(arg, str):
        arg = [arg]

    for x in arg:
        logger.trace(f'local addres: {x}')
        try:
            retval.append( ipaddress.ip_address(x) )
        except ValueError:
            logger.debug(f'Assuming:{x} is a hostname.')
            retval.append(x)
            pass
        pass
    return retval

def validateIpAddress(arg):
    ''' validate and clean up network addressing '''
    if arg.strip() == '': return ''
    split = arg.split('/')
    logger.trace(f'convert network address: {split[0]}')
    if split != '':
        retval = ipaddress.ip_address(split[0])
    else:
        logger.warning(f'Host with invalid ip address.')
        retval = ''
        pass
    return retval

def validateAsnRange(arg):
    ''' Check format, and expand the ASNs '''
    if isinstance(arg, tuple) or isinstance(arg, list):
        retval = [ int(x) for x in arg ]
    else:
        try:
            low, high = [ int(x) for x in arg.split(':') ]
            retval = list(range(low, high + 1))
        except:
            retval = ast.literal_eval(arg)
        pass
    return retval

class StringYaml(YAML):
    def dumps(self, data, **kw):
        stream = StringIO()
        YAML.dump(self, data, stream, **kw)
        return stream.getvalue()

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg == None:
        return ''
    return arg

@attr.s
class Sitecfg(object):
    alerts = attr.ib(default='', kw_only=True)
    asn_range = attr.ib(default='', kw_only=True, converter=validateAsnRange)
    aws_access_key_id = attr.ib(default='', kw_only=True, converter=nonone)
    aws_secret_access_key = attr.ib(default='', kw_only=True, converter=nonone)
    domain = attr.ib(default='', kw_only=True)
    locus = attr.ib(default='', kw_only=True)
    ipv4 = attr.ib(default = '192.168.2.0/24', kw_only=True, converter=validateNetworkAddress)
    ipv6 = attr.ib(default = 'fd86:ea04:1116::/64', kw_only=True, converter=validateNetworkAddress)
    portbase = attr.ib(default = 58822, kw_only=True, converter=int)
    publickey = attr.ib(default='', kw_only=True, converter=nonone)
    privatekey = attr.ib(default='', kw_only=True)
    route53 = attr.ib(default='', kw_only=True, converter=nonone)
    MSK  = attr.ib(default='', kw_only=True)

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['MSK']
        del m2['ipv4']
        return m2
    pass

@attr.s
class Host(object):
    hostname = attr.ib()
    sitecfg  = attr.ib()
    asn      = attr.ib(default=0, kw_only=True, converter=int)
    octet    = attr.ib(default=0, kw_only=True, converter=int)
    local_ipv4  = attr.ib(default= '', kw_only=True, converter=validateLocalAddresses)
    local_ipv6  = attr.ib(default= '', kw_only=True, converter=validateLocalAddresses)
    public_key  = attr.ib(default=f'', kw_only=True)
    local_networks   = attr.ib(default = '', kw_only=True)
    public_key_file  = attr.ib(default=f'', kw_only=True)
    private_key_file = attr.ib(default=f'', kw_only=True)
    uuid = attr.ib()

    def endport(self):
        ''' returns the octet added to the site.portbase '''
        retval = self.sitecfg.portbase + self.octet
        return retval

    def publish(self):
        if self.private_key_file == '':
            self.private_key_file =f'/etc/wireguard/{self.sitecfg.locus}_priv'
        m2 = { attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__") }
        m2['local_ipv4'] = [ str(x) for x in self.local_ipv4 ]
        m2['local_ipv6'] = [ str(x) for x in self.local_ipv6 ]
        del m2['hostname']
        del m2['sitecfg']
        logger.trace(pprint.pformat(m2))
        return self.hostname, m2

    def update(self, host):
        ''' update host from a new record 
        '''
        if self.uuid != host.uuid:
            raise HostMismatch

        hostname, hdict = host.publish()

        if self.hostname != hostname:
            self.info(f'Hostname Update: {self.hostname} => {hostname}')
            self.hostname = hostname
            pass

        for k, v in hdict.items():
            if k == 'asn': continue
            if k == 'octet': continue
            logger.trace(f'host update: {k}: {getattr(self, k)} => {v}')
            setattr(self, k, v)
            continue

        return True
    pass

def load_private_key(keyfile: str) -> PrivateKey
    ''' read key from a keyfile '''
    return loadkey(keyfile, PrivateKey)

def load_public_key(keyfile: str) -> PublicKey
    ''' read key from a keyfile '''
    return loadkey(keyfile, PublicKey)

def loadkey(keyfile: str, method: Union[PrivateKey, PublicKey]) -> Union[PrivateKey, PublicKey]:
    ''' read key from a keyfile '''
    content = open(keyfile, 'r').read()
    pk = keyimport(content, method)
    return pk

def keyimport(key: Union[str, bytes],  method: Union[PrivateKey, PublicKey]) -> Union[PrivateKey, PublicKey]:
    ''' uudecode a key '''
    logger.trace(f'keyimport: {type(key)}-{repr(key)}')
    try:
        content = base64.decodebytes(key.encode('ascii')).strip()
        logger.trace(f'{len(content)}:{repr(content)} // {len(key)}:{repr(key)}')
    except binascii.Error:
        logger.debug(r'base64 decode fails - assume raw key.')
        content = key.encode('ascii')
        pass
    logger.debug(f'Create KM Object key:{len(key)} / raw:{len(content)}')
    pk = method(content)
    logger.debug(f'Encoded: {keyexport(pk)}')
    return pk

def keyexport(key: Union[PublicKey, PrivateKey]) -> str:
    ''' encode a key '''
    logger.trace(f'keydecode: {type(key)}-{repr(key)}')
    retval = base64.encodebytes(key.encode()).decode().strip()
    logger.trace(f'{repr(key)}-{type(key)} / {repr(retval)}-{type(retval)}')
    return retval

def loadconfig(fn: str) -> list:
    ''' load config from disk
        
        fn: YAML file.
    '''
    yaml = YAML(typ='rt')
    with open(fn) as yamlfile:
        y = yaml.load(yamlfile)
        pass

    logger.trace(f'Global: {y.get("global")}')
    logger.trace(f'Hosts: {y.get("hosts").keys()}')

    sitecfg = Sitecfg(**y.get('global', {}))

    if sitecfg.privatekey > '':
        if os.path.exists(sitecfg.privatekey):
            sitecfg.MSK = load_private_key(sitecfg.privatekey)
        else:
            sitecfg.MSK = genkey(sitecfg.privatekey)
            pass
        pass

    if sitecfg.publickey > '':
        logger.trace(f'Decode Public Key: {sitecfg.publickey}')
        sitecfg.publickey = keyimport(sitecfg.publickey, PublicKey)
    else:
        sitecfg.publickey = sitecfg.MSK.public_key
        pass

    logger.trace(f'{sitecfg.MSK.public_key} /-/ {sitecfg.publickey}')
    if sitecfg.MSK.public_key != sitecfg.publickey:
        logger.error('PublicKey and Private Key Mismatch.')
        print('')
        sys.exit(2)
        pass

    hosts = []
    for k, v in y.get('hosts',{}).items():
        h = Host(k, sitecfg, **v)
        hosts.append(h)
        continue
    return sitecfg, hosts

def saveconfig(site: Sitecfg, hosts: list, fn: str):
    ''' commit config to disk 

        site: Sitecfg
        hosts: List of Hosts
    '''
    if isinstance(site.publickey, PublicKey):
        site.publickey = keyexport(site.publickey)
        pass

    dumphosts = { h.hostname: h.publish()[1] for h in hosts }
    publish = { 'global': site.publish(),
                'hosts': dumphosts }

    yaml=StringYaml(typ='rt')

    if fn:
        logger.debug(f'Writing file: {fn}')
        with open(fn, 'w') as outfile:
            yaml.dump(publish, outfile)
    else:
        logger.info(f'Dumping to screen.')
        print(yaml.dumps(publish))
        pass
    return

def genkey(keyfile):
    ''' create a key, and save it to file {keyfile} '''
    newKey = PrivateKey.generate()
    content = base64.encodebytes(newKey.encode())
    with open(keyfile, 'w') as kf:
        kf.write(content.decode())
    return newKey

def _km_process(km: Union[str, bytes], handler: Union[PrivateKey, PublicKey]):
    ''' convert a km to private/public key (handler) else. '''
    if isinstance(km, str):
        logger.trace(f'Convert keymaterial to ASCII bytes.')
        km = km.encode('ascii')
        pass

    logger.trace(f'Attempt to remove base64 wrapper.')
    try:
        decode = base64.decodebytes(km)
    except binascii.Error:
        logger.trace('base64 decode failed, assume it is a raw key.')
        decode = km
        pass
    retval = handler(decode)

    return retval

def decrypt(secret: Union[PrivateKey, str, bytes], public: Union[PublicKey, str, bytes], cipher: Union[str, bytes]):
    ''' encrypt a host blob target

    secret is either a UUEncoded Key or a realized PrivateKey
    public is either a UUEncoded Key or a realized PublicKey

    '''
    if not isinstance(secret, PrivateKey):
        SSK = _km_process(secret, PrivateKey)
    else:
        SSK = secret
        pass

    if not isinstance(public, PublicKey):
        PPK = _km_process(public, PublicKey)
    else:
        PPK = public
        pass

    if isinstance(cipher, str):
        logger.trace(f'convert cipher[str] to ASCII.')
        cipher = cipher.encode('ascii')
        pass

    try:
        cipher = base64.decodebytes(cipher)
    except binascii.Error:
        logger.trace(f'cipher appears to be raw')

    sBox = Box(SSK, PPK)
    output = sBox.decrypt(cipher)
    return (SSK, PPK, output)

def splitOrderedList(data):
    ''' take incoming encoded text, look for split order markers '''
    if data[0].find(':') > -1:
        logger.trace(f'Ordered DNS List Published: {data}')
        slist = []
        for r in data:
            if not r or r.strip() == '': continue
            k, v = r.split(':')
            slist.append((k, v))
            continue
        #sortlist = sorted([ (x[0], x[1]) for x.split(':') in response ])
        sortlist = natsorted(slist)
        retval = "".join([ x[1] for x in sortlist ])
    else:
        logger.trace(f'Unordered DNS List Published.')
        retval = "".join(data)
        pass

    return retval

def dns_query(domain: str) -> str:
    ''' return the record from the DNS '''
    answer = dns.resolver.query(domain,"TXT").response.answer[0]
    response = []
    for item in answer:
        logger.trace(f'{item} // {type(item)}')
        item = str(item).replace(' ', '\n').replace('"', '')
        response += item.split('\n')
        continue

    retval = splitOrderedList(response)
    logger.trace(f'Avengers Assembled: {retval}')
    return retval

def fetch_domain(domain: str) -> str:
    ''' return the decoded domain package '''

    output = dns_query(domain)
    logger.trace(f'{type(output)}')
    text = base64.decodebytes(str(output).encode('ascii'))
    logger.trace(f'Output: {text} // {type(text)}')
    yaml=YAML(typ='rt')
    retval = yaml.load(text)
    for k, v in retval.items():
        if isinstance(v, bytes):
            retval[k] = v.decode()
            continue
        continue
    return retval

def get_local_addresses_with_interfaces() -> (list, list):
    ''' return a list of tuples, (iface, address) '''
    addr4 = []
    addr6 = []
    for x in ifaddr.get_adapters():
        for a in x.ips:
            if a.is_IPv4:
                addr4.append((x.name, a.ip))
            elif a.is_IPv6:
                addr6.append((x.name, a.ip[0]))
                continue
            else:
                print(f'Nothing: {a.ip}')
            continue
        continue
    return (addr4, addr6)

def get_local_addresses() -> (list, list):
    ''' get local addresses sans interface '''
    addr4, addr6 = get_local_addresses_with_interfaces()
    return ([ x[1] for x in addr4 ], [ x[1] for x in addr6 ])

def filter_private(addr: list) -> list:
    ''' remote rfc1918 addresses from a list '''
    retval = []
    for x in addr:
        ip = ipaddress.ip_address(x)
        if ip.is_private:
            continue
        retval.append(x)
        continue
    return retval

def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

def LoggerConfig(debug: bool, trace: bool):
    '''
    Setup logging configuration.
    '''
    if not debug and not trace:
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        pass

    if debug:
        logger.info('Debug')
        logger.remove()
        logger.add(sys.stdout, level='DEBUG')
        pass

    if trace:
        logger.info('Trace')
        logger.remove()
        logger.add(sys.stdout, level='TRACE')
        pass

    pass

def CheckConfig(site, hosts):
    ''' verify Wireguard Core YAML Config, Subnets, etc '''
    maxcount = len(hosts) + 5

    asn_list    = []
    hosts_asn_fix = []

    octet_list      = []
    hosts_octet_fix = []

    # log the existing IPs
    for h in hosts:
        if not h.octet or h.octet == 0 or h.octet in octet_list:
            logger.warning(f"{h.hostname} invalid / missing / duplicate octet.")
            hosts_octet_fix.append(h)
        else:
            logger.trace(f'{h.hostname} octet normal. {h.octet}')
            octet_list.append(h.octet)
            pass

        if not h.asn or h.asn == 0:
            hosts_asn_fix.append(h)
        else:
            if h.asn in asn_list:
                logger.error(f'ASN Collision: {h.asn} {h}')
                hosts_asn_fix.append(h)
            else:
                asn_list.append(int(h.asn))
            pass
        continue

    try:
        octet_base = max(octet_list) + 1
    except ValueError:
        octet_base = 1
        pass

    for h in hosts_octet_fix:
        logger.trace(f"{h.hostname} octet: {h.octet} => {octet_base}")
        h.octet = octet_base
        octet_base += 1
        continue

    sset = set(site.asn_range)
    aset = set(asn_list)
    open_asn = list(sset - aset)
    if len(open_asn) == 0:
        logger.error("ASN Space Exhausted")
        pass

    for h in hosts_asn_fix:
        logger.trace(f'Checkout ASN for host: {h.hostname}')
        while len(open_asn):
            newasn = open_asn.pop(0)
            if newasn in asn_list:
                logger.error(f'ASN Collision Attempt: {newasn} for host {h.hostname}')
                newasn = None
                continue
            break
        if newasn:
            logger.trace(f'New ASN For Host: {h.hostname} => {newasn}')
            h.asn = newasn
        else:
            logger.error(f'No ASN Available for host: {h.hostname}')
            sys.exit(2)
            pass
        continue

    return site, hosts

##
## load template
## configure local settings
## build a matrix of hosts:ips
## Ensure that all of the hosts are consistent
## back-fill the matrix from the empties
##

@click.command()
@click.version_option(VERSION)
@click.option('--debug','-d', is_flag=True, default=False)
@click.option('--trace','-t', is_flag=True, default=False)
@click.argument('infile')
@click.argument('outfile', default='')
def cli(debug, trace, infile, outfile):
    if not debug:
        logger.info('Debug')
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        pass
    if trace:
        logger.info('Trace')
        logger.remove()
        logger.add(sys.stdout, level='TRACE')
        pass

    logger.trace(f'Core CLI')
    site, hosts = loadconfig(infile)
    site, hosts = CheckConfig(site, hosts)
    saveconfig(site, hosts, outfile)
    return (0)


if __name__ == "__main__":
    sys.exit(cli())
    pass
