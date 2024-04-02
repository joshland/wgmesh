#!/usr/bin/env python3
''' host function library '''

# Create the host basics locally
import re
import sys
import ifaddr
import netaddr

from typing import List, Dict, Tuple
from loguru import logger

from .version import VERSION

import ipaddress

class MixedInterface(Exception): pass
class NoInterface(Exception): pass

def get_local_addresses_with_interfaces(filter: List[str] = []) -> Tuple[list, list]:
    ''' return a list of tuples, (iface, address) '''
    addr4 = []
    addr6 = []
    for x in ifaddr.get_adapters():
        if x.name in filter:
            logger.debug(f'Ignore filtered interface {x}')
            continue
        logger.debug(f'gather details for interface {x}')
        for a in x.ips:
            if a.is_IPv4:
                addr4.append((x.name, a.ip))
                logger.trace(f'add {x.name}->{a.ip}')
            elif a.is_IPv6:
                addr6.append((x.name, a.ip[0]))
                logger.trace(f'add {x.name}->{a.ip[0]}')
                continue
            else:
                logger.debug(f"{x.name} has no addresses")
            continue
        continue
    logger.trace(f'retval: 4:{addr4} 6:{addr6}')
    return addr4, addr6

def get_local_addresses() -> Tuple[list, list]:
    ''' get local addresses sans interface '''
    addr4, addr6 = get_local_addresses_with_interfaces()
    return ([ x[1] for x in addr4 ], [ x[1] for x in addr6 ])

def find_trust():
    ''' return the trust(private) interface '''
    public, private = find_interfaces()
    if private:
        return private
    else:
        raise NoInterface

def find_public():
    ''' return the trust(private) interface '''
    public, private = find_interfaces()
    if public:
        return public
    else:
        raise NoInterface

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

def find_interfaces():
    ''' return the public interface '''
    all = get_local_addresses_with_interfaces()
    public4  = []
    trust4 = []
    public6  = []
    trust6 = []
    retval = (None, None)

    for iface, addr in all[0] + all[1]:
        logger.trace(f'Located IP Address: {iface} / {addr}')
        addr = ipaddress.ip_address(addr)
        if addr.version == 4:
            apub = public4
            atru = trust4
        else:
            apub = public6
            atru = trust6
            pass

        if addr.is_private:
            if iface in atru: continue
            if getattr(addr, 'is_link_local', False):
                continue
            if iface in apub: 
                raise MixedInterface
            logger.debug(f'Private address {addr} on interface {iface}.')
            atru.append(iface)
        else:
            if iface in apub: continue
            if iface in atru:
                raise MixedInterface
            logger.debug(f'Public address {addr} on interface {iface}.')
            apub.append(iface)
            continue
        continue

    if len(public4) == 1 and len(trust4) == 1:
        retval = (public4[0], trust4[0])
    elif len(public6) == 1 and len(trust6) == 1:
        retval = (public6[0], trust6[0])
    elif len(public6) == 1 and len(trust4) == 1:
        retval = (public6[0], trust4[0])
        pass

    return retval
