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
from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, encrypt

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