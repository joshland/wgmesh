#!/usr/bin/env python3

##
## CLI Tools
##

import os, sys, socket, time
import glob, copy

import click
from wgapp.db import Database 

from loguru import logger

import jinja2

SHELL_TEMPLATE = 'wgapp/templates/render.txt'

dbfiles = {}
N = '\n'


def logit(trace, debug):
    ''' initialize logging '''
    logger.remove()
    logger.add(sys.stderr, level='ERROR')
    logger.add(sys.stdout, level='INFO')

    if debug:
        logger.remove()
        logger.add(sys.stderr, level='DEBUG')
        pass

    if trace:
        logger.remove()        
        logger.add(sys.stderr, level='TRACE')
        pass

    pass

def loadFiles():
    global dbfiles
    
    for dataFile in glob.glob("*.yaml"):
        if dataFile in dbfiles:
            continue
        dbfiles[dataFile] = Database(dataFile)
        continue    
    return True

@click.group()
@click.option('--trace', '-t', default=False, required=False, is_flag=True)
@click.option('--debug', '-d', default=False, required=False, is_flag=True)
def main(trace, debug):
    global database

    logit(trace, debug)
    loadFiles()
    pass

@main.command()
def db_list():
    ''' report available sites, detail site(s) if given '''
    global dbfiles, N 

    print('Databases:')
    print('{N}'.join( [ f'  {x}' for x in dbfiles.keys() ] ))
    print(f'{N}(note: if only a single file is present, it is the default.)')
    return

@main.command()
@click.option('--dbname','-n', type=str, help='DB File to use, if there are more than one.', required=False)
@click.argument('site', required=False)
def site_list(dbname, site):
    ''' report available sites, detail site(s) if given '''
    global N

    db = loadDatabase(dbname)

    print('Sites')
    print(f'{N}'.join( f'  {x}' for x in db.data['sites'].keys()))
    logger.debug(f"List: {list(db.data['sites'].keys())}")

    return

def loadDatabase(dbname):
    ''' load the database '''
    global dbfiles

    if dbname:
        db = dbfiles[dbname]
    elif len(dbfiles) == 1:
        db = list(dbfiles.values())[0]
    else:
        logger.error('You must choose a database file.')
        return False

    return db


def getSiteScript(db, sitename):
    ''' get the shell script for a site '''
    site = db.getsite(sitename)

    templateLoader = jinja2.FileSystemLoader( searchpath="./" )
    templateEnv    = jinja2.Environment( loader=templateLoader )
    template       = templateEnv.get_template( SHELL_TEMPLATE )
    thisSite       = copy.copy(db.getsite(sitename))
    thisSite['peers'] = db.getpeers(sitename)
    thisSite['device'] = db.data['global']['wgdevice']

    templateVars   = {'data': thisSite}
    # Finally, process the template to produce our final text.
    outputText = template.render( templateVars )
    return outputText

@main.command()
@click.option('--dbname','-n', type=str, help='DB File to use, if there are more than one.', required=False)
@click.argument('sitename')
def render(dbname, sitename):
    ''' report available sites, detail site(s) if given '''

    logger.trace(f"Render: {list(sitename)}")

    db = loadDatabase(dbname)
    outputText = getSiteScript(db, sitename)
    print(outputText)
    return

@main.command()
@click.option('--dbname','-n', type=str, help='DB File to use, if there are more than one.', required=False)
@click.argument('folder')
def publish(dbname, folder):
    ''' report available sites, detail site(s) if given '''
    global dbfiles, N

    db = loadDatabase(dbname)
    logger.trace(f"Publish")

    sitelist = [ (k, v['hostname'])  for k, v in db.data['sites'].items()  ]

    if os.path.exists(folder) and not os.path.isdir(folder):
        logger.error(f"{folder} exists, and it is not a directory. ")
        return -1
    
    if not os.path.exists(folder):
        logger.trace(f'create folder: {folder}')
        os.mkdir(folder)
        pass

    xmit = ""
    for site, host in sitelist:
        output = getSiteScript(db, site)
        outfile = os.path.join(folder, f'{host}.sh')
        xmit += f"scp {host}.sh eis@{host}:{N}"
        with open(outfile, 'w') as f:
            logger.info(f'Write: {outfile}')
            f.write(output)
        continue

    script = os.path.join(folder, 'publish.sh')
    open(script, 'w').write(xmit)
    logger.info(f'Write: {script}')
    return

if __name__ == "__main__":
    __name__ = 'wgcli'
    main(obj={})
    sys.exit(cli())
