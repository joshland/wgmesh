#!/usr/bin/env python3
''' sited data definition and validator functions '''

from logging import warning
import os
import sys
import uuid
import ipaddress
from uuid import UUID
from io import StringIO
from itertools import chain
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from loguru import logger
from typing import Dict, List, Union

from ruamel.yaml import YAML
from munch import munchify, unmunchify, Munch
from attrs import define, validators, field
from nacl.public import PrivateKey, PublicKey, Box

from .crypto import keyexport, load_secret_key, load_public_key
from .datalib import nonone, collapse_asn_list, expandRange
from .datalib import message_encode, message_decode
from .transforms import EncryptedAWSSecrets
from .store_dns import DNSDataClass

class HostMismatch(Exception):
    ''' Mismach in the host'''
    pass

def convertAsnRange(arg):
    ''' Check format, and expand the ASNs '''
    if arg == '':
        raise ValueError("site asn_range parameter missing, blank or empty")
    logger.trace(f'Unpack ASN {arg}')
    if isinstance(arg, str):
        arg = arg.split(',')
    logger.trace(f'Expand and flatten: {arg}')
    retval = list(chain.from_iterable(([ expandRange(x) for x in arg ])))
    logger.trace(f'Flattened ASN Range: {retval}')
    return retval

empty_set = [ '', None ]

def convertNetworkAddress(arg):
    ''' validate and clean up network addressing '''
    logger.trace(f'convert network address: {arg}')
    if arg not in empty_set:
        retval = ipaddress.ip_network(arg)
    else:
        retval = arg
    return retval

def convertAddressBlocks(arg: Union[str, list]) -> list:
    ''' validate and clean up network addressing '''
    retval = []
    if isinstance(arg, str):
        arg = [arg] if arg != '' else []

    for x in arg:
        logger.trace(f'local addres: {x}')
        retval.append( ipaddress.ip_network(x) )
        continue

    return retval

def convertIPAddress(arg):
    ''' validate and clean up network addressing '''
    if arg.strip() == '':
        return ''
    split = arg.split('/')
    logger.trace(f'convert network address: {split}')
    if split != '':
        retval = ipaddress.ip_address(split[0])
    else:
        logger.warning('Host with invalid ip address.')
        retval = ''
        pass
    return retval

def convertUUID(arg):
    ''' load UUID from site '''
    if arg.strip() == '':
        raise ValueError('empty string from host in invalid')
    retval = uuid.UUID(arg)
    return retval

@define
class Host(object):
    ''' dataclass for host objects '''
    uuid:             UUID = field(converter=convertUUID)
    hostname:          str = field()
    sitecfg:        object = field()
    asn:               int = field(default=-1, converter=int)
    octet:             int = field(default=-1, converter=int)
    @octet.validator
    def validateOctet(self, attr, arg):
        ''' register valid octets with the siteobject '''
        if arg > -1:
            self.sitecfg.register_octet(arg, self.uuid)
        else:
            self.octet = self.sitecfg.checkout_octet(self.uuid)
            pass
        pass
    local_ipv4: List[IPv4Address] = field(default='', converter=convertAddressBlocks)
    local_ipv6: List[IPv6Address] = field(default='', converter=convertAddressBlocks)
    public_key_encoded: str = field(default='')
    local_networks:     str = field(default='')
    public_key_file:    str = field(default='')
    private_key_file:   str = field(default='')

    def validate(self):
        ''' ensure that asn and octet are set for this node '''
        if self.octet == -1:
            self.octet = self.sitecfg.checkout_octet()

    def encrypt_message(self, message: str) -> str:
        ''' encrypt a message with the host public key for transmission or posting '''
        message_box = self.sitecfg.get_site_message_box(self.public_key)
        secure_message = message_box.encrypt( message )
        retval = message_encode(secure_message)
        return retval

    def endport(self):
        ''' returns the octet added to the site.portbase '''
        retval = self.sitecfg.site.portbase + self.octet
        return retval

    def endpoint_addresses(self):
        ''' return a formatted list of endpoint IP addresses '''
        return ','.join([ str(x) for x in self.local_ipv4 + self.local_ipv6 if str(x) > '' ]),

    def publish(self):
        ''' export the class data as a dictionary, render objects as lists '''
        ## fixme: this should be a transform class
        retval = {'uuid': str(self.uuid),
                  'hostname': self.hostname,
                  'asn': self.asn,
                  'octet': self.octet,
                  'local_ipv4': [ str(x) for x in self.local_ipv4 ],
                  'local_ipv6': [ str(x) for x in self.local_ipv6 ],
                  'public_key_encoded': self.public_key_encoded,
                  'local_networks': self.local_networks,
                  'public_key_file': self.public_key_file,
                  'private_key_file': self.private_key_file,
                  }
        retval = munchify(retval)
        logger.trace(f'published host: {retval}')
        return retval

    def update(self, host):
        ''' update host from a new record '''
        if self.uuid != host.uuid:
            raise HostMismatch
        hostname, hdict = host.publish()
        if self.hostname != hostname:
            self.info(f'Hostname Update: {self.hostname} => {hostname}')
            self.hostname = hostname
            pass
        for k, v in hdict.items():
            if k == 'asn':
                continue
            if k == 'octet':
                continue
            logger.trace(f'host update: {k}: {getattr(self, k)} => {v}')
            setattr(self, k, v)
            continue
        return True
    pass

@define
class Sitecfg:
    ''' dataclass for site configuration '''
    locus:                 str = field(default='')
    domain:                str = field(default='')
    tunnel_ipv4:   IPv4Network = field(default='', converter=convertNetworkAddress)
    tunnel_ipv6:   IPv6Network = field(default='', converter=convertNetworkAddress)
    portbase:              int = field(default = 58822, converter=int)
    asn_range:             str = field(default='', converter=convertAsnRange)
    asn_used:             list = field(default='')
    privatekey:            str = field(default='', converter=nonone)
    publickey:             str = field(default='')
    route53:               str = field(default='', converter=nonone)
    aws_credentials:       str = field(default='')
    aws_access_key:        str = field(default='')
    aws_secret_access_key: str = field(default='')
    alerts: str = field(default='', validator=validators.instance_of(str))
    _hosts:         List[Host] = field(default=[])
    _octet_map:           Dict = field(default={})
    _octets:         List[int] = field(default=[0])
    _master_aws_secrets: EncryptedAWSSecrets = field(default=None)
    _master_site_key:Union[PrivateKey,None] = field(default=None)
    @alerts.validator
    def _check_alerts(self, attr, arg):
        ''' check for valid email address '''
        if not len(arg):
            return
        address, domain = arg.split('@')
        parts = domain.split('.')
        if len(parts) == 1:
            raise ValueError(f'{attr} address incorrect/incomplete: {arg}')
        return

    def open_keys(self):
        ''' try to unpack the keys '''
        logger.trace('open_keys')
        if self._master_site_key:
            logger.error("Attempting to re-load the site key. Abort")
            sys.exit(2)

        if self.privatekey > '':
            if os.path.exists(self.privatekey):
                logger.trace(f'Open and read: {self.privatekey}')
                with open(self.privatekey, 'r', encoding='utf-8') as keyfile:
                    self._master_site_key = load_secret_key(keyfile.read())
                    pass
                pass
        else:
            logger.error('Missing global->secret_key. Run init?')
            sys.exit(3)

        if self.publickey:
            public_key = load_public_key(self.publickey)
            if public_key != self._master_site_key.public_key:
                logger.error(f'Public key in Site config does not match {self.privatekey}')
                sys.exit(1)
            logger.trace('Public key matches site key.')
        else:
            self.publickey = keyexport(self._master_site_key.public_key)

        if (self.aws_access_key and self.aws_secret_access_key) and self.aws_credentials == '':
            self._master_aws_secrets = EncryptedAWSSecrets(self.aws_access_key, self.aws_secret_access_key)
            self.aws_access_key = ''
            self.aws_secret_access_key = ''
        elif self.aws_credentials > '':
            box = self.get_message_box(self._master_site_key.public_key)
            self._master_aws_secrets = EncryptedAWSSecrets.load_encrypted_credentials(self.aws_credentials, box)
            self.aws_access_key = self._master_aws_secrets.access_key
            self.aws_secret_access_key = self._master_aws_secrets.secret_key
            pass

    def checkout_octet(self, host_uuid):
        ''' checkout the next octet '''
        self._octets.sort()
        retval = self._octets[-1] + 1
        self.register_octet(retval, host_uuid)
        return retval

    def get_message_box(self, publickey: PublicKey) -> Box:
        ''' setup an SBox for decryption
        publickey: public key from the host who encrypted the message
        '''
        if isinstance(publickey, str):
            publickey = load_public_key(publickey)

        logger.trace(f'Create Box ({type(self._master_site_key)}), ({type(publickey)})')
        logger.trace(f'Create Box: Pub:({publickey})')
        retval = Box(self._master_site_key, publickey)
        return retval

    def register_octet(self, arg, host_uuid):
        ''' register a new octet as being used '''
        try:
            if self._octet_map[host_uuid] == arg:
                return True
        except KeyError:
            pass
        if arg in self._octets:
            logger.warning(f'Attempted to register an existing octet: {arg}')
            logger.warning(f'Octets: {self._octet_map}')
        else:
            self._octets.append(arg)
            self._octet_map[host_uuid] = arg
            logger.trace(f'assign octet {arg}')
        return arg

    def publish_public_payload(self):
        ''' return the site payload dictionay '''
        return munchify({'locus': self.locus, 'publickey': keyexport(self._master_site_key.public_key)})

    def publish(self):
        ''' export local configuration for storage or transport '''
        if (self._master_aws_secrets and self.aws_credentials == '') and self._master_site_key:
            box = self.get_message_box(self._master_site_key.public_key)
            self.aws_credentials = self._master_aws_secrets.export_encrypted_credentials(box)

        retval = {'locus': self.locus,
                  'tunnel_ipv4': str(self.tunnel_ipv4) if self.tunnel_ipv4 else None,
                  'tunnel_ipv6': str(self.tunnel_ipv6) if self.tunnel_ipv6 else None,
                  'domain': self.domain,
                  'portbase': self.portbase,
                  'asn_range': collapse_asn_list(self.asn_range),
                  'asn_used': self.asn_used,
                  'publickey': self.publickey,
                  'privatekey': self.privatekey,
                  'alerts': self.alerts,
                  'route53': self.route53,
                  'aws_credentials': '',
                  'aws_access_key': self.aws_access_key,
                  'aws_secret_access_key': self.aws_secret_access_key,
                  }
        retval = munchify(retval)

        if self._master_aws_secrets:
            retval.aws_credentials = self._master_aws_secrets.export_encrypted_credentials(
                self.get_message_box(self._master_site_key.public_key))
            del retval['aws_access_key']
            del retval['aws_secret_access_key']

        if isinstance(retval.publickey, PublicKey):
            retval.publickey = keyexport(self.publickey)

        return retval

    def update_aws_credentials(self, access_key: str, secret_key: str):
        ''' set the AWS credentials '''
        logger.debug(f'Update AWS Credentials: {access_key} / [{"*"*len(secret_key)}]')
        self._master_aws_secrets.access_key = access_key
        self._master_aws_secrets.secret_key = secret_key
        return True

    def unregister_octet(self, host_uuid):
        ''' remove a host from the octet map '''
        logger.debug(f"Clean Octet Map: {self._octet_map[host_uuid]}")
        del self._octet_map[host_uuid]

class Site:
    ''' site=>*hosts site handler class '''
    def __init__(self, sourcefile: str = None, sitecfg_args: dict = {}):
        if sourcefile and sitecfg_args:
            raise ValueError('Use either sourcefile or sitecfg_args')
        if sourcefile:
            self._load_from_file(sourcefile)
        else:
            self.site = Sitecfg(**sitecfg_args)
            self.hosts = []

    def _load_from_file(self, source_file):
        ''' load data from the source_file '''
        yaml = YAML(typ='rt')

        y = yaml.load(source_file)
        logger.debug(f'{list(y.keys())}')
        logger.trace(f'Global: {y.get("global")}')
        logger.trace(f'Hosts: {y.get("hosts")}')
        self.site = Sitecfg(**y.get('global', {}))
        logger.trace('Open Site Keys.')
        self.site.open_keys()
        logger.trace(f'Site Public Key: {self.site.publickey}')
        self.hosts = []
        for k, v in y.get('hosts',{}).items():
            logger.trace(f'Load Host: {k}:{v}')
            self.host_add(v)
            continue

    def check_asn_sanity(self):
        ''' check and return asns to site '''
        found = []
        needs_update = []
        for x in self.hosts:
            logger.trace(f'ASN sanity check: {x.hostname}->{x.asn}')
            if x.asn in ['', None, -1]:
                needs_update.append(x)
            else:
                found.append(x.asn)
            continue
        ## overwrite the asn_used
        logger.trace(f'ASN Sanity Check: Used/Found: {self.site.asn_used} => {found}')
        logger.trace(f'ASN Sanity Check: Needs Update: {needs_update}')
        self.site.asn_used = found
        complete_range = set(self.site.asn_range)
        logger.trace(f'Available ASNs: {complete_range}')
        used_range = set(found)
        logger.trace(f'Used ASNs: {used_range}')
        open_range = list(complete_range - used_range)
        logger.debug(f'Open ASN Set: {open_range}')
        if len(needs_update) > len(open_range):
            logger.warning('Exhausted ASN Range')
        for x in needs_update:
            if len(complete_range) == 0:
                logger.warning('Insufficient ASN range. Aborting.')
                break
            x.asn = complete_range.pop()
            self.site.asn_used.append(x.asn)
            logger.trace(f'Updated ASN: {x.hostname}({str(x.uuid)})=>{x.asn}')
            continue
        pass

    def save_site_config(self):
        ''' export Site and Hosts as a Yaml File

            site: Sitecfg
            hosts: List of Hosts
        '''
        logger.trace('save site to yaml')
        sitedata = self.site.publish()
        logger.debug(f'{list(sitedata.keys())}')
        publish = { 'global': unmunchify(sitedata),
                    'hosts': { h.uuid: unmunchify(h) for h in [ h.publish() for h in self.hosts if h ] },}
        logger.trace(f'Serialize Yaml Data: {publish}')
        yaml = YAML(typ='rt')
        buffer = StringIO()
        yaml.dump(publish, buffer)
        buffer.seek(0)
        return buffer.read()


    def checkout_octet(self, host_uuid):
        ''' checkout the next octet '''
        return self.site.checkout_octet(host_uuid)

    def get_host_by_uuid(self, host_uuid: UUID):
        ''' lookup a host by a UUID '''
        for x in self.hosts:
            if x.uuid == host_uuid:
                return x
        return None

    def publish(self):
        '''return site publisher '''
        return self.site.publish()

    def host_add(self, host_args):
        ''' create/register a host '''
        host = Host(sitecfg=self, **host_args)
        self.hosts.append(host)
        return host

    def host_delete(self, host_uuid):
        ''' delete a host by UUID '''
        host = None
        index = -1
        for index, h in enumerate(self.hosts):
            if h.uuid == host_uuid:
                logger.debug(f'Matched UUID: {host_uuid}=>{h}')
                host = h
                break
            continue
        if not host or index == -1:
            logger.debug(f'no host found for removal: {host_uuid}')
            raise ValueError('no matching uuid found')
        logger.debug(f'Remove Host: {index}=>{host.uuid}({host.uuid}')
        logger.trace(f'cleaning: {self.hosts}')
        del self.hosts[index]
        self.site.unregister_octet(host_uuid)
        return True

    def get_site_message_box(self, publickey: PublicKey) -> Box:
        ''' setup an SBox for decryption
        publickey: public key from the host who encrypted the message
        '''
        return self.site.get_message_box(publickey)

    def register_octet(self, arg, host_uuid):
        ''' register a new octet as being used '''
        return self.site.register_octet(arg, host_uuid)
