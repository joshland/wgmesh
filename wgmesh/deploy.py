#!/usr/bin/env python3

# Create the host basics locally
import sys, os
import click
import loguru
import socket
import nacl.utils
import attr, inspect
import hashlib, uuid

from loguru import logger
from ruamel import yaml
from ruamel.yaml import RoundTripLoader, RoundTripDumper
from nacl.public import PrivateKey, Box, PublicKey
from wgmesh.core import *
from wgmesh import HostDB
from wgmesh.templates import render, shorewall_interfaces, shorewall_rules, namespace_start, vrf_start
from .endpointdb import *

import pprint
import base64

import ipaddress   

lect = """
---
site: <domain>
hosts:
  [hostname]:
    - pubkey: XXXXXXyyyyyyyyyZZZZZ
    - local_networks: 10.1.1.0/24,11.1.1.0/24,2006::/64
    - remote_address: 5.5.5.5
  [hostname]:
    - pubkey: XXXXXXyyyyyyyyyZZZZZ
    - local_networks: 20.1.1.0/24,21.1.1.0/24,2006:1::/64
    - remote_address: 6.6.6.6
"""

lect = """
  {hostname}:
    - pubkey: {pubkey}
    - local_networks: {localnets}
    - remote_address: {remoteaddr}
"""

wire_template = """
#
# Peering template generated template for {myhost} => {Hostname}
#
[Interface]
PrivateKey = {private_key}
Address    = {tunnel_addresses}
ListenPort = {local_port}

# {Hostname}
[Peer]
PublicKey  = {public_key}
Endpoint   = {remote_address}
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepAlive = 25
"""

class MixedInterface(Exception): pass
class NoInterface(Exception): pass

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

def check_update_file(buffer, path):
    ''' compare existing contents to calculated buffers, write if different '''
    try:
        current = open(path, 'r').read()
        if current == buffer:
            logger.trace(f'buffer matches {path}, no update needed.')
            update = False
        update = True
    except FileNotFoundError:
        logger.trace(f'Unable to load file {path}')
        update = True

    try:
        if update:
            logger.trace(f'Write file: {path}.')
            with open(path,'w') as ifacefile:
                ifacefile.write(buffer)
                pass
            pass
    except FileNotFoundError:
        logger.error(f'Unknown problem (re)creatign {path}')
        sys.exit(1)
        pass
    except PermissionError:
        logger.error(f'Permission Denied Writing: {path}')
        sys.exit(1)
        pass

@click.command()
@click.option( '--debug',    '-d', default=False, is_flag=True, help="Activate Debug Logging." )
@click.option( '--trace',    '-t', default=False, is_flag=True, help="Activate Trace Logging." )
@click.option( '--dry-run',  '-n', default=False, is_flag=True, help="Don't write any files."  )
@click.option( '--locus',    '-l', default='', help="Manually set Mesh Locus."      )
@click.option( '--pubkey',   '-p', default='', help="Manually set Mesh Public Key." )
@click.option( '--hostname', '-h', default='', help="Override local hostname."      )
@click.option( '--inbound',  '-i', default='', help="Inbound interface."  )
@click.option( '--outbound', '-o', default='', help="Outbound interface." )
@click.option( '--trust',    '-T', default='', help="Trust interface."    )
@click.option( '--trustip',  '-I', default='', help="Trust interface IP address."    )
@click.argument('domain')
def cli(debug: bool, trace: bool, dry_run: bool, locus: str, pubkey: str, hostname: str,
        inbound: str, outbound: str, trust: str, trustip: str, domain: str):
    f''' Setup localhost, provide registration with master controller.

    wgdeploy: deploy wireguard and FRR configuration.

    '''
    LoggerConfig(debug, trace)

    if not locus or not pubkey:
        try:
            dominfo = fetch_domain(domain)
        except:
            logger.error(f'DNS Query Timeout: {domain}')
            sys.exit(1)
        logger.trace(f'domain info: {dominfo}') 
        pass

    if locus == '':
        locus = dominfo['locus']
        pass

    if pubkey == '':
        pubkey = dominfo['publickey']
        pass

    #hostconfig
    hostconfig = CheckLocalHostConfig(domain, locus, pubkey)
    import pprint
    print(f'|-----------------------------------|')
    pprint.pprint(hostconfig)

    #Get UUID
    target = f'{hostconfig.host.uuid}.{domain}'
    try:
        crypt = dns_query(target)
    except:
        logger.error(f"DNS Exception: {target}")
        print()
        raise
        sys.exit(1)
        pass

    message = decrypt(hostconfig.host.SSK, hostconfig.site.PPK, crypt)[2]
    o = yaml.load(message, Loader=yaml.RoundTripLoader)

    print("HostConfig:")
    pprint.pprint(hostconfig.publish(), indent=2)
    print()
    print('Published:')
    pprint.pprint(o, indent=2)

    portbase = o['portbase']
    site = o['site']
    tunnel, cidr = o['remote'].split('/')
    mykey = open(hostconfig.host.private_key_file, 'r').read().strip()

    template_args = {
        'ports': [],
        'wireguard_interfaces': [],
    }

    if inbound:
        template_args['interface_public'] = inbound
    else:
        template_args['interface_public'] = hostconfig.host.interface_public

    if outbound:
        template_args['interface_outbound'] = outbound
    else:
        template_args['interface_outbound'] = hostconfig.host.interface_outbound

    if trust:
        template_args['interface_trust'] = trust
    else:
        template_args['interface_trust'] = hostconfig.host.interface_trust

    if trustip:
        template_args['interface_trust_ip'] = trustip
    else:
        template_args['interface_trust_ip'] = hostconfig.host.interface_trust_ip

    for index, item in enumerate(o['hosts'].items()):
        host, values = item
        remotes = ''
        if len(values['remote']):
            addrs = values['remote'].split(',')
            remotes = (',').join( [ f"{str(x)}:{values['remoteport']}" for x in addrs ] )
            pass

        portpoints = [ o['octet'] ]
        portpoints.append( values['localport'] - o['portbase'] )
        netbits = ':'.join( [ str(x) for x in sorted(portpoints, reverse=True) ] )
        epaddr = f'{tunnel}{netbits}:{o["octet"]}/{cidr}'

        fulfill = {
            'myhost':           hostconfig.host.hostname,
            'private_key':      mykey,
            'tunnel_addresses': epaddr,
            'local_port':       values['localport'],
            'Hostname':         host,
            'public_key':       values['key'],
            'remote_address':   remotes,
            'octet':            o['octet'],
            'interface_public':    template_args['interface_public'],
            'interface_trust':     template_args['interface_trust'],
            'interface_outbound':  template_args['interface_outbound'],
        }

        template_args['asn'] = o['asn']
        template_args['octet'] = o['octet']
        template_args['ports'].append( values['localport'] )
        template_args['wireguard_interfaces'].append(f'wg{index}')

        print()
        print(f'writing: /etc/wireguard/wg{index}.conf')
    
        if dry_run:
            logger.info(f'Dry-run Mode.')
            print(wire_template.format(**fulfill))
        else:
            with open(f'/etc/wireguard/wg{index}.conf', 'w') as writer:
                writer.write(wire_template.format(**fulfill))
                pass
            pass
        continue

    interfaces = render(shorewall_interfaces, template_args)
    dnatrules  = render(shorewall_rules,      template_args)
    namespace  = render(namespace_start,      template_args)
    vrf        = render(vrf_start,      template_args)

    check_update_file(dnatrules,  '/etc/shorewall/rules')
    check_update_file(interfaces, '/etc/shorewall/interfaces')
    check_update_file(namespace,  '/usr/local/sbin/namestart_start')
    check_update_file(vrf,        '/usr/local/sbin/vrf_start')

    return 0

if __name__ == "__main__":
    sys.exit(Main())