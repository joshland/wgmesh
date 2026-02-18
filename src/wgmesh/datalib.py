#!/usr/bin/env python3
"""command data functions"""

import os
import sys
import json
import base64
import dns.resolver
from uuid import UUID, uuid4
from typing import Union, Any, Callable

import attrs
from munch import munchify
from loguru import logger
from natsort import natsorted


class InvalidHostName(Exception):
    """DNS subsystem returned that a domain name was invalid / nonexistent"""

    pass


class InvalidMessage(Exception):
    """message payload was invalid"""

    pass


emptyValuesTuple = (None, "")


def asdict(
    inst: Any,
    formatter: Union[Callable[[str], str], None] = None,
    *args: Any,
    **kwargs: Any,
) -> Any:
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
    return munchify(
        {
            attribute_name: value
            for attribute_name, value in attrs.asdict(inst, *args, **kwargs).items()
            if attribute_name[0] != "_"
        }
    )


def check_update_file(buffer, path):
    """compare existing contents to calculated buffers, write if different"""
    dirname = os.path.abspath(os.path.dirname(path))
    logger.trace(f"Make Directories: {dirname}")
    os.makedirs(dirname)
    try:
        with open(path, "r") as cf:
            current = cf.read()
        if current == buffer:
            logger.debug(f"skip file {path}, no update needed.")
            update = False
        else:
            update = True
    except FileNotFoundError:
        logger.trace(f"Unable to load file {path}")
        update = True
    try:
        if update:
            logger.debug(f"Write file: {path}")
            with open(path, "w") as ifacefile:
                ifacefile.write(buffer)
                pass
            pass
    except FileNotFoundError:
        logger.error(f"Unknown problem (re)creatign {path}")
        sys.exit(1)
    except PermissionError:
        logger.error(f"Permission Denied Writing: {path}")
        sys.exit(1)


def collapse_asn_list(arg):
    """collapse the asn list into a minimalist range list"""
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
                consecutive = [
                    asn,
                ]
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
            str_elements.append(f"{sorted_asns[0]}:{sorted_asns[-1]}")
        continue
    return ",".join(str_elements)


def convert_uuid_uuid(value):
    """convert a UUID string into a UUID object, or create a new UUID"""
    if value.strip() in emptyValuesTuple:
        retval = str(uuid4())
    else:
        retval = UUID(value)
    return retval


def decode_domain(dnspayload: str) -> dict:
    """return the decoded domain package"""
    text = message_decode(dnspayload)
    logger.trace(f"Output: {text} // {type(text)}")
    try:
        retval = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.debug(f"Invalid JSON payload from DNS: {text}")
        raise InvalidMessage from exc
    for k, v in retval.items():
        if isinstance(v, bytes):
            retval[k] = v.decode()
            continue
        continue
    return retval


def dns_query(domain: str) -> str:
    """return the record from the DNS"""
    try:
        answer = dns.resolver.resolve(domain, "TXT").response.answer[0]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        logger.error(f"Invalid Hostname {domain} / No TXT Record.")
        raise InvalidHostName from exc
    except Exception as exc:
        logger.error(f"DNS query failed for {domain}: {exc}")
        raise InvalidHostName from exc

    response = []
    for item in answer:
        logger.trace(f"{item} // {type(item)}")
        item = str(item).replace(" ", "\n").replace('"', "")
        response += item.split("\n")
        continue

    retval = sort_and_join_encoded_data(response)
    logger.trace(f"Avengers Assembled: {retval}")
    return retval


def expandRange(arg):
    """expand a range"""
    try:
        low, high = [int(x) for x in arg.split(":")]
        high += 1
    except ValueError:
        low = int(arg)
        high = low + 1
    return list(range(low, high))


def fetch_and_decode_record(domain_name: str, test_mode: str = "") -> dict:
    """gather a DNS record, and decode the embedded data"""
    if test_mode:
        dns_data = test_dns_query(domain_name, test_mode)
    else:
        dns_data = dns_query(domain_name)
    decoded_data = decode_domain(sort_and_join_encoded_data(dns_data))
    return decoded_data


def test_dns_query(domain: str, test_dir: str) -> list:
    """return the record from local test files instead of DNS"""
    from pathlib import Path

    site_file = Path(test_dir) / "site_record.json"

    if not site_file.exists():
        logger.error(f"Test DNS file not found: {site_file}")
        raise InvalidHostName(f"No test record for {domain}")

    with open(site_file, "r") as f:
        data = json.load(f)

    raw_payload = data.get("raw_payload", "")
    if not raw_payload:
        logger.error(f"No raw_payload in test file: {site_file}")
        raise InvalidHostName(f"Invalid test record for {domain}")

    return [raw_payload]


def test_dns_query_host(uuid: str, domain: str, test_dir: str) -> str:
    """return host record from local test files instead of DNS"""
    from pathlib import Path

    host_file = Path(test_dir) / f"host_{uuid}.json"

    if not host_file.exists():
        logger.error(f"Test DNS host file not found: {host_file}")
        raise InvalidHostName(f"No test record for {uuid}.{domain}")

    with open(host_file, "r") as f:
        data = json.load(f)

    raw_payload = data.get("raw_payload", "")
    if not raw_payload:
        logger.error(f"No raw_payload in test host file: {host_file}")
        raise InvalidHostName(f"Invalid test record for {uuid}.{domain}")

    return raw_payload


def message_decode(payload: Union[str, bytes], binary=False) -> Union[str, bytes]:
    """decode a base64 encoded message"""
    if isinstance(payload, str):
        payload = payload.encode("ascii")
    logger.debug(f"Decode message {len(payload)}::binary:{binary}")
    if binary:
        retval = base64.b64decode(payload)
    else:
        retval = base64.b64decode(payload).decode("utf-8")
    return retval


def message_encode(payload: Union[str, bytes]) -> str:
    """base64 encode a message"""
    if isinstance(payload, str):
        payload = payload.encode("ascii")
    return base64.b64encode(payload).decode("utf-8")


def nonone(arg):
    """eliminate the None and blanks"""
    if arg is None:
        return ""
    return arg


def sort_and_join_encoded_data(data):
    """take incoming encoded text, look for split order markers"""
    if data[0].find(":") > -1:
        logger.trace(f"Ordered DNS List Published: {data}")
        slist = []
        for r in data:
            if not r or r.strip() == "":
                continue
            k, v = r.split(":")
            slist.append((k, v))
            continue
        sortlist = natsorted(slist)
        retval = "".join([x[1] for x in sortlist])
    else:
        logger.trace("Unordered DNS List Published.")
        retval = "".join(data)
        pass
    return retval


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
