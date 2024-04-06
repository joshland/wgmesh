#!/usr/bin/env python3
''' command data functions '''
import typing
import attrs
import base64
from uuid import UUID, uuid4

from loguru import logger
from munch import munchify

emptyValuesTuple = (None, '')

def convert_uuid_uuid(value):
    if value.strip() in emptyValuesTuple:
        return str( uuid4() )
    else:
        return UUID(value)

def message_decode(payload: str|bytes, binary=False) -> str|bytes:
    ''' decode a base64 encoded message '''
    if isinstance(payload, str):
        payload = payload.encode('ascii')
    logger.debug(f'Decode message {len(payload)}::binary:{binary}')
    if binary:
        retval = base64.b64decode(payload)
    else:
        retval = base64.b64decode(payload).decode('utf-8')
    return retval

def message_encode(payload: str|bytes) -> str:
    ''' base64 encode a message '''
    if isinstance(payload, str):
        payload = payload.encode('ascii')
    return base64.b64encode(payload).decode('utf-8')

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg == None:
        return ''
    return arg

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
    return munchify({
        attribute_name: value
        for attribute_name, value in attrs.asdict(inst, *args, **kwargs).items()
        if attribute_name[0] != '_'
    })

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

