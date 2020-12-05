#!/usr/bin/env python3

##
## wgfrr.py
##

# created routes, and then exchange using FRR.
# My plan would prefer something like L6
import sys
import ipaddress
import click
import pprint
import yaml
import loguru
import attr, inspect

from loguru import logger

def validateNetworkAddress(arg):
    ''' validate and clean up network addressing '''
    logger.trace(f'convert network address: {arg}')
    retval = ipaddress.ip_network(arg)
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

@attr.s
class Sitecfg(object):
    alerts = attr.ib(default='', kw_only=True)
    domain = attr.ib(default='', kw_only=True)
    locus  = attr.ib(default='', kw_only=True)
    ipv4   = attr.ib(default = '192.168.2.1/24', kw_only=True, converter=validateNetworkAddress)
    ipv6   = attr.ib(default = 'fd86:ea04:1116::/64', kw_only=True, converter=validateNetworkAddress)

    def publish(self):
        #members = [attr for attr in dir(example) if not callable(getattr(example, attr)) and not attr.startswith("__")]
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        return m2

@attr.s
class Host(object):
    hostname = attr.ib()
    sitecfg = attr.ib()
    ipv4    = attr.ib(default= '', kw_only=True, converter=validateIpAddress)
    ipv6    = attr.ib(default= '', kw_only=True, converter=validateIpAddress)
    local_networks = attr.ib(default = '', kw_only=True)
    public_key = attr.ib(default=f'', kw_only=True)
    private_key_file = attr.ib(default=f'', kw_only=True)

    def publish(self):
        if self.private_key_file == '':
            self.private_key_file =f'/etc/wireguard/{self.sitecfg.locus}_priv'
        m2 = { attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__") }
        del m2['hostname']
        del m2['sitecfg']
        #pprint.pprint(m2)
        return self.hostname, m2


def loadconfig( fn: str ):
    ''' load config from disk
        
        fn: YAML file.
    '''
    with open(fn) as yamlfile:
        y = yaml.safe_load(yamlfile)
        pass

    logger.trace(f'Global: {y.get("global")}')
    logger.trace(f'Hosts: {y.get("hosts").keys()}')

    sitecfg = Sitecfg(**y.get('global', {}))
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
    dumphosts = { h.hostname: h.publish()[1] for h in hosts }
    publish = { 'global': site.publish(),
                'hosts': dumphosts }

    if fn:
        logger.info(f'Writing file: {fn}')
        with open(fn, 'w') as outfile:
            yaml.dump(publish, outfile)
    else:
        logger.info(f'Dumping to screen.')
        print(yaml.dump(publish))
        pass
    return

##
## load template
## configure local settings
## build a matrix of hosts:ips
## Ensure that all of the hosts are consistent
## back-fill the matrix from the empties
##

@click.command()
@click.option('--debug','-d', is_flag=True, default=False)
@click.option('--trace','-t', is_flag=True, default=False)
@click.argument('infile')
@click.argument('outfile', default='')
def Main(debug, trace, infile, outfile):
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

    site, hosts = loadconfig(infile)

    maxcount = len(hosts) + 5

    ipv4_master = []
    ipv6_master = []

    hosts4_to_be_adjusted = []
    hosts6_to_be_adjusted = []

    # log the existing IPs
    for h in hosts:
        if h.ipv4 == '' or h.ipv4 not in site.ipv4:
            logger.trace(f'Host needs ipv4 address: {h}')
            hosts4_to_be_adjusted.append(h)
        else:
            logger.trace(f'Host ipv4 address: {h}')
            ipv4_master.append(h.ipv4)
            pass

        if h.ipv6 == '' or h.ipv6 not in site.ipv6:
            logger.trace(f'Host needs ipv6 address: {h}')
            hosts6_to_be_adjusted.append(h)
        else:
            logger.trace(f'Host ipv6 address: {h}')
            ipv6_master.append(h.ipv6)
            pass
        continue
        
    for host in hosts4_to_be_adjusted:
        logger.debug(f'{host.hostname} needs ipv4 address.')

        for x in range(1, maxcount):
            addr = site.ipv4[x]
            if addr in ipv4_master:
                logger.trace(f'{addr} exists in the master list, rejecting.')
                continue
            break
        if x == maxcount:
            logger.error(f'ipv6 calculation failed for {host.hostname}.')
            sys.exit(1)
            pass

        logger.trace(f'Assign ipv{addr.version} address: {host.hostname} => {addr}')
        host.ipv4 = addr
        ipv4_master.append(addr)
        continue

    for host in hosts6_to_be_adjusted:
        logger.debug(f'{host.hostname} needs ipv6 address.')
        for x in range(1, maxcount):
            addr = site.ipv6[x]
            if addr in ipv6_master:
                logger.trace(f'{addr} exists in the master list, rejecting.')
                continue
            break
        if x == maxcount:
            logger.error(f'ipv6 calculation failed for {host.hostname}.')
            sys.exit(1)
            pass
        logger.trace(f'Assign ipv{addr.version} address: {host.hostname} => {addr}')
        host.ipv6 = addr
        ipv6_master.append(addr)
        continue

    saveconfig(site, hosts, outfile)
    return 0

if __name__ == "__main__":
    sys.exit(Main())