#!/usr/bin/env python3

##
## wgfrr.py
##

# created routes, and then exchange using FRR.
# My plan would prefer something like L6
import sys, os
import yaml
import click
import loguru
import attr, inspect
from loguru import logger

from wgmesh.core import loadconfig, saveconfig, CheckConfig, gen_local_config, encrypt

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
        fn = os.path.join(output, host.hostname)
        yfile = open(f'{fn}.yaml', 'w')
        bfile = open(f'{fn}.blob', 'w')
        data = {}
        for inst in gen_local_config(c):
            dev = inst['device']
            data[dev] = inst
            continue

        ydata = yaml.safe_dump(data)
        yfile.write(ydata)

        bfile.write(encrypt(host, ydata))
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