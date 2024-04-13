#!/usr/bin/env python3
''' command data functions '''
import base64
from uuid import UUID, uuid4
from typing import Union, Any, Callable

import attrs
from loguru import logger
from munch import munchify

emptyValuesTuple = (None, '')

def convert_uuid_uuid(value):
    ''' convert a UUID string into a UUID object, or create a new UUID '''
    if value.strip() in emptyValuesTuple:
        retval = str( uuid4() )
    else:
        retval = UUID(value)
    return retval

def expandRange(arg):
    ''' expand a range '''
    try:
        low, high = [ int(x) for x in arg.split(":") ]
        high += 1
    except ValueError:
        low = int(arg)
        high = low + 1
    return list(range(low, high))

def collapse_asn_list(arg):
    ''' collapse the asn list into a minimalist range list '''
    # Sort the list of VLAN IDs and exclude any with state set to absent
    list_elements: list[list[int]] = []
    consecutive: list[int] = []

    asn_list = sorted(arg)
    for asn in asn_list:
        if consecutive:
            if (asn - consecutive[-1]) <= 1:
                consecutive.append(asn)
            else:
                list_elements.append(consecutive)
                consecutive = [asn,]
        else:
            # Populate consecutive with the first element
            consecutive.append(asn)
        continue
    list_elements.append(consecutive)

    # Format the elements into a string
    str_elements: list[str] = []
    for element in list_elements:
        if len(element) == 1:
            str_elements.append(str(element[0]))
        else:
            sorted_asns = sorted(element)
            str_elements.append(f'{sorted_asns[0]}:{sorted_asns[-1]}')
        continue
    return ','.join(str_elements)

def message_decode(payload: Union[str,bytes], binary=False) -> Union[str,bytes]:
    ''' decode a base64 encoded message '''
    if isinstance(payload, str):
        payload = payload.encode('ascii')
    logger.debug(f'Decode message {len(payload)}::binary:{binary}')
    if binary:
        retval = base64.b64decode(payload)
    else:
        retval = base64.b64decode(payload).decode('utf-8')
    return retval

def message_encode(payload: Union[str,bytes]) -> str:
    ''' base64 encode a message '''
    if isinstance(payload, str):
        payload = payload.encode('ascii')
    return base64.b64encode(payload).decode('utf-8')

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg is None:
        return ''
    return arg

def asdict(inst: Any,
           formatter: Union[Callable[[str], str],None] = None,
           *args: Any, **kwargs: Any) -> dict[str, Any]:
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
