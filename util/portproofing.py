#!/usr/bin/env python3

## portproof.py

# Create test list, check for port collisions.
import sys
from wgcore import loadconfig, saveconfig, CheckConfig
import click
import loguru
import attr, inspect

from loguru import logger

@click.command()
@click.option('--debug','-d', is_flag=True, default=False, help="Activate Debug Logging.")
@click.option('--trace','-t', is_flag=True, default=False, help="Activate Trace Logging.")
@click.argument('infile')
def Main(debug, trace, infile):
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

    taken = []
    closed = []
    for me in hosts:
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
    return 0

if __name__ == "__main__":
    sys.exit(Main())