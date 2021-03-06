#!/usr/bin/env python3

# Create the host basics locally
import sys, os, pwd
import click
import loguru
import socket
import nacl.utils
import attr, inspect
import hashlib, uuid
import netaddr

from ruamel import yaml
from loguru import logger
from ruamel.yaml import RoundTripLoader, RoundTripDumper
from nacl.public import PrivateKey, Box, PublicKey
from .core import *
from .templates import render, shorewall_interfaces, shorewall_rules, bird_private, wireguard_conf
from .templates import ns_private, ns_tester, mesh_start
from .endpointdb import *

import pprint
import base64

import ipaddress   

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
            logger.debug(f'skip file {path}, no update needed.')
            update = False
        else:
            update = True
    except FileNotFoundError:
        logger.trace(f'Unable to load file {path}')
        update = True

    try:
        if update:
            logger.debug(f'Write file: {path}')
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
@click.option( '--asn',      '-a', default='', help="Manually set Local ASN."       )
@click.option( '--hostname', '-h', default='', help="Override local hostname."      )
@click.option( '--inbound',  '-i', default='', help="Inbound interface."  )
@click.option( '--outbound', '-o', default='', help="Outbound interface." )
@click.option( '--trust',    '-T', default='', help="Trust interface."    )
@click.option( '--trustip',  '-I', default='', help="Trust interface IP address."    )
@click.argument('domain')
def cli(debug: bool, trace: bool, dry_run: bool, locus: str, pubkey: str, asn: str,
        hostname: str, inbound: str, outbound: str, trust: str, trustip: str, domain: str):
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

    hostconfig = CheckLocalHostConfig(domain, locus, pubkey)

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
    deploy_message = yaml.load(message, Loader=yaml.RoundTripLoader)

    if trace:
        print("HostConfig:")
        pprint.pprint(hostconfig.publish(), indent=2)
        print()
        print('Published:')
        pprint.pprint(deploy_message, indent=2)
        pass

    portbase = deploy_message['portbase']
    site = deploy_message['site']
    tunnel_network = netaddr.IPNetwork(deploy_message['remote'])
    tunnel_net_base = str(tunnel_network.network).split('::')[0]
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
        pass

    template_args['wireguard_interfaces'] = {}
    template_args['cmds'] = {
        'binfping': hostconfig.host.cmdfping,
    }

    template_args['locus']     = hostconfig.site.locus
    template_args['myhost']    = hostconfig.host.hostname
    template_args['local_asn'] = deploy_message['asn']
    template_args['octet']     = deploy_message['octet']
    template_args['tunnel_remote'] = deploy_message['remote']
    template_args['routing_tables'] = {}

    for host, values in deploy_message['hosts'].items():
        index = values['localport'] - deploy_message['portbase']
        remotes = ''
        if len(values['remote']):
            addrs = values['remote'].split(',')
            remotes = (',').join( [ f"{str(x)}:{values['remoteport']}" for x in addrs ] )
            pass

        portpoints = [ deploy_message['octet'] ]
        portpoints.append( index )
        netbits = ''.join([ '{:02X}'.format(a) for a in sorted(portpoints, reverse=True) ])
        local_endpoint_addr = f'{tunnel_net_base}:{netbits}::{deploy_message["octet"]}/64'
        remote_endpoint_addr = f'{tunnel_net_base}:{netbits}::{index}'
        #route_table_id  = hostconfig.host.route_table_base + index
        #route_table_name = f'{hostconfig.site.locus}_wg{index}'
        #template_args['routing_tables'][f'wg{index}'] = { 'name': route_table_name, 'id': route_table_id}
        listen_address = template_args['interface_trust_ip'].split('/')[0]

        fulfill = {
            'myhost':           hostconfig.host.hostname,
            'Hostname':         host,
            'interface_outbound':  template_args['interface_outbound'],
            'interface_public':    template_args['interface_public'],
            'interface_trust':     template_args['interface_trust'],
            'listen_address':  listen_address,
            'local_port':       values['localport'],
            'octet':            deploy_message['octet'],
            'private_key':      mykey,
            'public_key':       values['key'],
            'remote_address':   remotes,
            #'route_table_id':   route_table_id,
            #'route_table_name': route_table_name,
            'tunnel_addresses': local_endpoint_addr,
        }

        template_args['ports'].append( values['localport'] )
        template_args['wireguard_interfaces'][f'wg{index}'] = [ remote_endpoint_addr, values['asn'] ]
        template_args['local_endpoint_addr'] = local_endpoint_addr

        wgconf = render(wireguard_conf, fulfill)
        # diable rt_tables for now
        #check_update_route_table(route_table_id, route_table_name)

        if dry_run:
            logger.info(f'Dry-run Mode.')
            print(wgconf)
        else:
            check_update_file(wgconf, f'/etc/wireguard/wg{index}.conf')
            pass
        continue

    interfaces = render(shorewall_interfaces, template_args)
    dnatrules  = render(shorewall_rules,      template_args)
    nssysvinit = render(ns_private,           template_args)
    tssysvinit = render(ns_tester,            template_args)
    meshstart  = render(mesh_start,           template_args)
    bird_priv  = render(bird_private,         template_args)

    check_update_file(dnatrules,  '/etc/shorewall/rules')
    check_update_file(interfaces, '/etc/shorewall/interfaces')
    check_update_file(nssysvinit, '/usr/local/sbin/ns-private')
    check_update_file(tssysvinit, '/usr/local/sbin/ns-tester')
    check_update_file(meshstart,  '/usr/local/sbin/mesh_wg_restart')
    check_update_file(bird_priv,  '/etc/bird/bird_private.conf')

    for x in (
        '/usr/local/sbin/mesh_ns_init',
        '/usr/local/sbin/mesh_wg_restart',
        '/usr/local/sbin/ns-private',
        '/usr/local/sbin/ns-tester'):
        os.chmod(x, 0o750)
        continue

    for x in ('/etc/shorewall/rules', '/etc/shorewall/interfaces', '/etc/bird/bird_private.conf'):
        os.chmod(x, 0o640)
        continue

    os.makedirs('/etc/bird/bird_private_local.d')

    buser  = pwd.getpwnam('bird').pw_uid
    bgroup = pwd.getpwnam('bird').pw_gid
    try:
        os.chown('/etc/bird/bird_private_local.d', buser, bgroup)
        os.chown('/etc/bird/bird_private.conf', buser, bgroup)
    except PermissionError:
        logger.warning(f'Failed to set ownership of /etc/bird/bird_private.conf')
    return 0

if __name__ == "__main__":
    sys.exit(Main())