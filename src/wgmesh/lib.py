#!/usr/bin/env python3
''' lib.py - resource library for file and configuration operations '''
import os
import sys
import attrs
import typing

from loguru import logger
from ruamel.yaml import YAML

from .crypto import load_secret_key, load_public_key
from .endpointdata import Endpoint
from .sitedata import Sitecfg

def LoggerConfig(debug: bool, trace: bool):
    '''
    Setup logging configuration.
    '''
    if not debug and not trace:
        logger.remove()
        logger.add(sys.stdout, level='INFO')
        pass

    if debug:
        logger.info('Debug')
        logger.remove()
        logger.add(sys.stdout, level='DEBUG')
        pass

    if trace:
        logger.info('Trace')
        logger.remove()
        logger.add(sys.stdout, level='TRACE')
        pass

    pass

def load_site_config(fn: str) -> tuple[Sitecfg, list]:
    ''' load site config from disk
        
        fn: YAML file.
    '''
    yaml = YAML(typ='rt')

    with open(fn) as yamlfile:
        y = yaml.load(yamlfile)
        pass

    logger.trace(f'Global: {y.get("global")}')
    logger.trace(f'Hosts: {y.get("hosts").keys()}')

    sitecfg = Sitecfg(**y.get('global', {}))
    sitecfg.openKeys()

    logger.trace(f'{sitecfg.MSK.public_key} /-/ {sitecfg.publickey}')

    hosts = []
    for k, v in y.get('hosts',{}).items():
        h = Host(k, sitecfg, **v)
        hosts.append(h)
        continue
    return sitecfg, hosts


def asdict(inst: typing.Any,
           formatter: typing.Callable[[str], str] | None = None,
           *args: typing.Any, **kwargs: typing.Any) -> dict[str, typing.Any]:
    """
    A utility version of :func:`attrs.asdict`.

    .. note::
        Using this function, you're able to specify a new parameter
        :paramref:`attrs_utils.asdict.formatter`.

        This is a Callable that applies to the name of each attribute
        of the given attrs-decorated object.

        Names formatted by it are used as keys in the resulting dictionary.
        https://github.com/python-attrs/attrs/issues/12
    """
    return {
        attribute_name: value
        for attribute_name, value in attrs.asdict(inst, *args, **kwargs).items()
        if attribute_name[0] != '_'
    }

def remove_secret(attribute_name: str) -> str:
    """
    A formatter function for protected attributes of an
    attrs-decorated object.

    It's intended to be used in :func:`attrs_utils.asdict`.

    :returns: attribute_name without a preceding underscore character.
    """
    return attribute_name[1:] if attribute_name[0] == "_" else attribute_name

def format_protected(attribute_name: str) -> str:
    """
    A formatter function for protected attributes of an
    attrs-decorated object.

    It's intended to be used in :func:`attrs_utils.asdict`.

    :returns: attribute_name without a preceding underscore character.
    """
    return attribute_name[1:] if attribute_name[0] == "_" else attribute_name

