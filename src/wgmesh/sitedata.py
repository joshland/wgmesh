#!/usr/bin/env python3
''' sited data definition and validator functions '''

import os
import sys
import uuid
import ipaddress
from uuid import UUID
from io import StringIO
from base64 import b64encode, b64decode
from itertools import chain
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from attr import asdict
from loguru import logger
from typing import Any, Dict, List, TextIO

from ruamel.yaml import YAML
from munch import munchify, unmunchify, Munch
from attrs import define, validators, field
from nacl.public import PrivateKey, PublicKey, Box

from .crypto import keyexport, load_secret_key, load_public_key
from .datalib import nonone
from .datalib import asdict as wgmesh_asdict
from .datalib import message_encode, message_decode
from .transforms import EncryptedAWSSecrets

class HostMismatch(Exception): pass
class MissingAsnConfig(Exception): pass

def check_asn_sanity(site, hosts):
    ''' check and return asns to site '''
    found = []
    for x in hosts:
        logger.trace(f'ASN sanity check: {x.hostname}->{x.asn}')
        if asn in site.asn_range:
            found.append(x.asn)
        else:
            logger.warning(f'Invalid ASN removed, {x.hostname}->{x.asn}')
            continue
        continue
    ## overwrite the asn_used
    logger.trace(f'ASN Sanity Check: {site.asn_used} => {found}')
    site.asn_used = found

def expandRange(arg):
    ''' expand a range '''
    try:
        low, high = [ int(x) for x in arg.split(":") ]
        high += 1
    except ValueError:
        low = int(arg)
        high = low + 1
    return list(range(low, high))

def convertAsnRange(arg):
    ''' Check format, and expand the ASNs '''
    if arg == '':
        raise ValueError("site asn_range parameter missing")
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

def convertAddressBlocks(arg: str|list) -> list:
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
    if arg.strip() == '': return ''
    split = arg.split('/')
    logger.trace(f'convert network address: {split}')
    if split != '':
        retval = ipaddress.ip_address(split[0])
    else:
        logger.warning(f'Host with invalid ip address.')
        retval = ''
        pass
    return retval

def convertUUID(arg):
    ''' load UUID from site '''
    if arg.strip() == '':
        raise ValueError('empty string from host in invalid')
    retval = uuid.UUID(arg)
    return retval

def collapse_asn_list(arg):
    ''' collapse the asn list into a minimalist range list '''
    # Sort the list of VLAN IDs and exclude any with state set to absent
    list_elements: list[list[int]] = []
    consecutive: list[int] = []

    asn_list = sorted(arg)
    for asn in asn_list:
        if consecutive:
            if (asn - consecutive[-1]) <= 1:
                consecutive.append(asn)
            else:
                list_elements.append(consecutive)
                consecutive = [asn,]
        else:
            # Populate consecutive with the first element
            consecutive.append(asn)
        continue
    list_elements.append(consecutive)

    # Format the elements into a string
    str_elements: list[str] = []
    for element in list_elements:
        if len(element) == 1:
            str_elements.append(str(element[0]))
        else:
            sorted_asns = sorted(element)
            str_elements.append(f'{sorted_asns[0]}:{sorted_asns[-1]}')
        continue
    return ','.join(str_elements)

@define
class Host(object):
    uuid:                UUID = field(converter=convertUUID)
    hostname:             str = field()
    sitecfg:           object = field()
    asn:                  int = field(default=-1, converter=int)
    @asn.validator
    def validateAsn(self, attr, arg):
        ''' register valid ASNs with the siteobject '''
        if arg > -1:
            self.sitecfg.register_asn(arg, self.uuid)
        else:
            self.asn = self.sitecfg.checkout_asn(self.uuid)
            pass
        pass
    octet:                int = field(default=-1, converter=int)
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
    public_key: PublicKey|str = field(default='')
    local_networks:       str = field(default='')
    public_key_file:      str = field(default='')
    private_key_file:     str = field(default='')

    def validate(self):
        ''' ensure that asn and octet are set for this node '''
        if self.asn == -1:
            self.asn = self.sitecfg.checkout_asn()
        if self.octet == -1:
            self.octet = self.sitecfg.checkout_octet()

    def encrypt_message(self, message: str) -> str:
        ''' encrypt a message with the host public key for transmission or posting '''
        message_box = self.sitecfg.get_message_box(self.public_key)
        secure_message = message_box.encrypt( message )
        retval = message_encode(secure_message)
        return retval

    def endport(self):
        ''' returns the octet added to the site.portbase '''
        retval = self.sitecfg.portbase + self.octet
        return retval

    def endpoint_addresses(self):
        ''' return a formatted list of endpoint IP addresses '''
        return ','.join([ str(x) for x in self.local_ipv4 + self.local_ipv6 if str(x) > '' ]),

    def publish_peer_deploy(self):
        ''' publish wgdeploy node details '''
        retval = munchify ({
            'locus':     self.site.locus,
            'site':      self.sitecfg.domain,
            'portbase':  self.sitecfg.portbase,
            'octet':     self.octet,
            'asn':       self.asn,
            'localport': self.endport(),
            'remote':    self.endpoint_addresses(),
            'hosts':     [] })

        for host in self.sitecfg.hosts:
            retval.hosts.append( {
                                'key': host.key,
                                'asn': host.asn,
                                'localport': host.endport(),
                                'remoteport': self.endport(),
                                'remote': host.endpoint_addresses(), })

        return retval

    def publish(self):
        ''' export the class data as a dictionary, render objects as lists '''
        ## fixme: this should be a transform class
        retval = {'uuid': str(self.uuid),
                  'hostname': self.hostname,
                  'asn': self.asn,
                  'octet': self.octet,
                  'local_ipv4': [ str(x) for x in self.local_ipv4 ],
                  'local_ipv6': [ str(x) for x in self.local_ipv6 ],
                  'public_key': keyexport(self.public_key),
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
            if k == 'asn': continue
            if k == 'octet': continue
            logger.trace(f'host update: {k}: {getattr(self, k)} => {v}')
            setattr(self, k, v)
            continue

        return True
    pass

@define
class Sitecfg:
    locus:                 str = field(default='')
    domain:                str = field(default='')
    tunnel_ipv4:   IPv4Network = field(default='', converter=convertNetworkAddress)
    tunnel_ipv6:   IPv6Network = field(default='', converter=convertNetworkAddress)
    portbase:              int = field(default = 58822, converter=int)
    asn_range:  str|tuple|list = field(default='', converter=convertAsnRange)
    asn_used:             list = field(default=[])
    privatekey:            str = field(default='', converter=nonone)
    publickey:             str = field(default='')
    route53:               str = field(default='', converter=nonone)
    aws_credentials:       str = field(default='')
    aws_access_key:        str = field(default='')
    aws_secret_access_key: str = field(default='')
    alerts: str = field(default='', validator=validators.instance_of(str))
    _asn_map:             Dict = field(default={})
    _hosts:         List[Host] = field(default=[])
    _octet_map:           Dict = field(default={})
    _octets:         List[int] = field(default=[0])
    _open_asn:       List[int] = field(default=[])
    _registeredHosts:     Dict = field(default={})
    _master_aws_secrets: EncryptedAWSSecrets = field(default=None)
    _master_site_key:PrivateKey|None = field(default=None)
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
    @classmethod
    def load_site_config(cls, source_file: TextIO):
        ''' load site config from disk

            source_file: YAML file.
        '''
        yaml = YAML(typ='rt')

        y = yaml.load(source_file)
        logger.trace(f'{y}')
        logger.trace(f'Global: {y.get("global")}')
        logger.trace(f'Hosts: {y.get("hosts")}')

        sitecfg = Sitecfg(**y.get('global', {}))
        sitecfg.open_keys()

        logger.trace(f'{sitecfg._master_site_key.public_key} /-/ {sitecfg.publickey}')

        hosts = []
        for k, v in y.get('hosts',{}).items():
            logger.trace(f'Load Host: {k}:{v}')
            h = Host(sitecfg=sitecfg, **v)
            sitecfg.host_add(h)
            continue
        check_asn_sanity(sitecfg, hosts)
        return sitecfg
    def host_add(self, host: Host):
        ''' add host '''
        self._hosts.append(host)

    def host_delete(self, uuid):
        ''' delete a host by UUID '''
        host = None
        for index, h in enumerate(self._hosts):
            if str(h.uuid) == uuid:
                logger.debug(f'Matched UUID: {uuid}=>{h}')
                host = h
                break
            continue

        if not host:
            raise ValueError('no matching uuid found')

        logger.debug(f'Remove Host: {index}=>{host}')
        logger.trace(f'cleaning: {self._hosts}')
        del self._hosts[index]
        logger.debug(f"Clean ASN Map: {self._asn_map[host.uuid]}")
        logger.trace(f'cleaning: {self._asn_map}')
        del self._asn_map[host.uuid]
        logger.debug(f"Clean Octet Map: {self._octet_map[host.uuid]}")
        del self._octet_map[host.uuid]
        logger.trace(f'cleaning: {self._octet_map}')
        return True

    def save_site_config(self):
        ''' commit config to disk

            site: Sitecfg
            hosts: List of Hosts
        '''
        logger.trace(f'Save - Site:{self}')
        sitedata = self.publish()
        logger.debug(f'{list(sitedata.keys())}')

        publish = { 'global': unmunchify(sitedata),
                    'hosts': { h.uuid: unmunchify(h) for h in [ h.publish() for h in self._hosts if h ] },}

        logger.trace(f'Serialize Yaml Data: {publish}')
        yaml = YAML(typ='rt')
        buffer = StringIO()
        yaml.dump(publish, buffer)
        buffer.seek(0)

        return buffer.read()
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
    def get_host_by_uuid(self, uuid: UUID):
        ''' lookup a host by a UUID '''
        retval = self._asn_map.get(uuid, None)

        return retval

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
                  'asn_used': list(self._asn_map.values()),
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

        if isinstance(retval.publickey, PublicKey):
            retval.publickey = keyexport(self.publickey)

        return retval

    def register_asn(self, arg, uuid):
        ''' log asn used by a host '''
        logger.trace(f'request asn {arg} - ASNs:{len(self.asn_used)}/{len(self.asn_range)} registry:{self._asn_map}')

        try:
            if self._asn_map[uuid] == arg:
                return True
        except KeyError:
            pass

        if arg not in self.asn_range:
            raise ValueError('ASN invalid, not within approved range')
        if arg in self._asn_map.values():
            for k, v in self._asn_map.items():
                if v == arg:
                    logger.trace(f'Conflicting ASN found: {str(k)} conflicts with {str(uuid)}')
                    logger.error(f'Used ASNs: {self.asn_used} {str(k)} conflicts with {str(uuid)}')
                    logger.trace(f'Available ASNs: {self.asn_range}')
                    raise ValueError('Duplicate ASN')
                continue
            pass

        logger.trace(f'register asn {arg}')
        self._asn_map[uuid] = arg
        return True

    def checkout_asn(self, uuid):
        ''' retrieve an available ASN from the pool '''
        # fixme: we need a --fix-asns options
        if not len(self._open_asn):
            logger.trace(f'_open_asn empty, rebuilding')
            self.calculate_open_asn()
        logger.trace(f'open_asn before: {self._open_asn}')
        retval = self._open_asn.pop(0)
        logger.trace(f'fetch asn: {retval} => open_asn before: {self._open_asn}')
        self.register_asn(retval, uuid)
        return retval

    def register_octet(self, arg, uuid):
        ''' register a new octet as being used '''
        try:
            if self._octet_map[uuid] == arg:
                return True
        except KeyError:
            pass
        if arg in self._octets:
            logger.warning('Attempted to register an existing octet: {octet}')
        else:
            self._octets.append(arg)
            self._octet_map[uuid] = arg
            logger.trace(f'assign octet {arg}')
        return arg

    def checkout_octet(self, uuid):
        ''' checkout the next octet '''
        retval = self._octets[-1] + 1
        self.register_octet(retval, uuid)
        return retval

    def calculate_open_asn(self):
        ''' try to find open_asns '''
        ## setup ASN list
        sset = set(self.asn_range)
        logger.trace(f'Available ASNs: {sset}')
        aset = set(self.asn_used)
        logger.trace(f'Used ASNs: {aset}')
        self._open_asn = list(sset - aset)
        logger.debug(f'Open ASN Set: {self._open_asn}')
        if len(self._open_asn) == 0:
            logger.error("ASN Space Exhausted")
            sys.exit(4)

    def open_keys(self):
        ''' try to unpack the keys '''
        logger.trace('open_keys')
        if self._master_site_key:
            logger.error("Attempting to re-load the site key. Abort")
            sys.exit(2)

        if self.privatekey > '':
            if os.path.exists(self.privatekey):
                logger.trace(f'Open and read: {self.privatekey}')
                with open(self.privatekey, 'r') as keyfile:
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
            logger.trace(f'Public key matches site key.')
        else:
            self.publickey = keyexport(self._master_site_key.public_key)

        if (self.aws_access_key and self.aws_secret_access_key) and self.aws_credentials == '':
            self._master_aws_secrets = EncryptedAWSSecrets(self.aws_access_key, self.aws_secret_access_key)
            self.aws_access_key = ''
            self.aws_secret_access_key = ''
        elif self.aws_credentials > '':
            box = self.get_message_box(self._master_site_key.public_key)
            self._master_aws_secrets = EncryptedAWSSecrets.load_encrypted_credentials(self.aws_credentials, box)
            pass

    pass


