''' sited data definition and validator functions '''

import os
import sys
import uuid
from uuid import UUID
import ipaddress

from attr import asdict
from click import open_file
from loguru import logger
from typing import Any, Dict, List
from itertools import chain
from attrs import define, validators, field
from nacl.public import PrivateKey, PublicKey
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from wgmesh.core import keyexport

from .crypto import load_secret_key, load_public_key
from .datalib import nonone
from .datalib import asdict as wgmesh_asdict

class HostMismatch(Exception): pass
class MissingAsnConfig(Exception): pass

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

def convertNetworkAddress(arg):
    ''' validate and clean up network addressing '''
    logger.trace(f'convert network address: {arg}')
    retval = ipaddress.ip_network(arg)
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

def collaps_asn_list(arg):
    ''' collapse the asn list into a minimalist range list '''
    # Sort the list of VLAN IDs and exclude any with state set to absent
    asn_list = sorted(arg)

    list_elements: list[list[int]] = []

    consecutive: list[int] = []

    # Format of a VLAN list is VLAN IDs separated with commas.  If any VLANS are consecutive, the range is separated
    # with a hyphen.
    # EG:
    #   420,600-601,603,605-607,609
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
class Sitecfg:
    alerts: str = field(default='', validator=validators.instance_of(str))
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

    asn_range:  str|tuple|list = field(default='', converter=convertAsnRange)
    asn_used:             list = field(default=[])
    aws_access_key:        str = field(default='')
    aws_secret_access_key: str = field(default='')
    domain:                str = field(default='')
    locus:                 str = field(default='')
    tunnel_ipv4:   IPv4Network = field(default='192.168.12.0/24', converter=convertNetworkAddress)
    tunnel_ipv6:   IPv6Network = field(default='fd86:ea04:1116::/64', converter=convertNetworkAddress)
    portbase:              int = field(default = 58822, converter=int)
    publickey:             str = field(default='', converter=nonone)
    privatekey:            str = field(default='', converter=nonone)
    route53:               str = field(default='', converter=nonone)
    _asn_map:             Dict = field(default={})
    _octet_map:           Dict = field(default={})
    _octets:         List[int] = field(default=[0])
    _master_site_key:PrivateKey|None = field(default='')

    def publish_public_payload(self):
        ''' return the site payload dictionay '''
        return {'locus': self.locus, 'publickey': keyexport(self._master_site_key.public_key) }

    def publish(self):
        ''' export local configuration for storage or transport '''
        retval = wgmesh_asdict(self)
        if isinstance(retval['publickey'], PublicKey):
            retval['publickey'] = keyexport(self.publickey)
        retval['tunnel_ipv4'] = str(self.tunnel_ipv4)
        retval['tunnel_ipv6'] = str(self.tunnel_ipv6)
        retval['asn_range'] = collaps_asn_list(self.asn_range)
        return retval

    def register_asn(self, arg, uuid):
        ''' log asn used by a host '''
        logger.trace(f'request asn {arg}')

        try:
            if self._asn_map[uuid] == arg:
                return True
        except KeyError:
            pass

        if arg not in self.asn_range:
            raise ValueError('ASN invalid, not within approved range')
        if arg in self.asn_used:
            logger.error(f'Used ASNs: {self.asn_used}')
            logger.trace(f'Available ASNs: {self.asn_range}')
            raise ValueError('Duplicate ASN')
        logger.trace(f'register asn {arg}')
        self.asn_used.append(arg)
        self._asn_map[uuid] = arg
        return True

    def checkout_asn(self, uuid):
        ''' retrieve an available ASN from the pool '''
        sset = set(self.asn_range)
        aset = set(self.asn_used)
        open_asn = list(sset - aset)
        if len(open_asn) == 0:
            logger.error("ASN Space Exhausted")
            sys.exit(4)
            pass

        retval = open_asn.pop(0)
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
            logger.error('Missing global->secret_key.  Run init?')
            sys.exit(3)

        if self.publickey:
            public_key = load_public_key(self.publickey)
            if public_key != self._master_site_key.public_key:
                logger.error(f'Public key in Site config does not match {self.privatekey}')
                sys.exit(1)
                pass
            logger.trace(f'Public key matches site key.')
            self.public_key = public_key
            pass
    pass

@define
class Host(object):
    hostname:             str = field()
    sitecfg:          Sitecfg = field()
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
    uuid:                UUID = field(default='', converter=convertUUID)

    def validate(self):
        ''' ensure that asn and octet are set for this node '''
        if self.asn == -1:
            self.asn = self.sitecfg.checkout_asn()
        if self.octet == -1:
            self.octet = self.sitecfg.checkut_octet()

    def endport(self):
        ''' returns the octet added to the site.portbase '''
        retval = self.sitecfg.portbase + self.octet
        return retval

    def publish(self):
        ''' export the class data as a dictionary, render objects as lists '''
        retval = asdict(self)
        retval['local_ipv4'] = [ str(x) for x in self.local_ipv4 ]
        retval['local_ipv6'] = [ str(x) for x in self.local_ipv6 ]
        retval['publickey'] = keyexport(self.public_key)
        del retval['hostname']
        del retval['sitecfg']
        logger.trace(f'Host Pack: {retval}')
        return self.hostname, retval

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


