#!/usr/bin/env python3

##
## wgfrr.py
##

# created routes, and then exchange using FRR.
# My plan would prefer something like L6
import sys, os
import click
import loguru
import attr, inspect
from loguru import logger

from wgcore import loadconfig, saveconfig, CheckConfig, gen_local_config

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.option('--update','-u', is_flag=True, default=False, help="Update YAML file with changes.")
@click.option('--output', '-o', default='output', help="[folder] for changes (default: 'output')")
@click.option('--publish', '-p', is_flag=True, default=False, help="Publish to [folder] (default: False)")
@click.argument('infile')
@click.argument('sites', required=False, nargs=-1)
def cli(debug, trace, update, output, publish, infile, sites):
    f''' Update or publish INFILE to Folder specified by OUTPUT {output} for [SITES] '''
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

    site, hosts = CheckConfig(*loadconfig(infile))

    # find the hosts with public keys
    # create new archive messages encrypted to those destinations
    # store them somwhere
    possibles = []
    for h in hosts:
        if h.public_key > '':
            possibles.append(h)
            continue
        continue

    #create output folder
    if os.path.exists(output) and not os.path.isdir(output):
        logger.error(f'{output} exists and is not a folder.')
        sys.exit(2)
        pass

    if not os.path.exists(output):
        os.mkdir(output)
        pass
    
    for host in possibles:
        if os.path.exists()
        for inst in gen_local_config(c):
            #ceate folder

    taken = []
    closed = []
    for me in hosts:
        ## source port == remote address last digit
        ## remote port == my last digit
        pb = site.portbase
        my_octet = int(str(me.ipv4).split('.')[-1])
        for this in hosts:
            if me.hostname == this.hostname: continue
            this_octet = int(str(this.ipv4).split('.')[-1])
            sideA = f'{this.hostname}:{pb + my_octet}'
            sideB = f'{me.hostname}:{pb + this_octet}'
            temp = [ sideA, sideB ]
            temp.sort()
            if sideA in taken or sideB in taken:
                if temp not in closed:
                    print(f'ERROR: {temp} Collsion but something WRONG.')
                    pass
            else:
                closed.append(temp)
            continue
        continue

    #for site in sites|*:
    #    for endpoint in hosts-not-site:
    #        write wgX with config
    #        Setup for 0.0.0.0
    #        write frr bgp stanzas
    #        ## Synchronize PublicKeys
    #        ## Regenerate Private/Publick Keys
    #        ## Site-based key approval?
    #        ## Signed site keys?
    #        continue
    #    continue
    return 0

if __name__ == "__main__":
    sys.exit(Main())