#!/usr/bin/env python3
"""endpoint data definition and validators"""

from base64 import b64decode
import socket
from uuid import UUID
from io import StringIO
from typing import List, TextIO

from loguru import logger
from ruamel.yaml import YAML
from attrs import define, field
from munch import munchify, unmunchify
from nacl.public import PrivateKey, PublicKey, Box

from .crypto import keyexport, load_public_key, load_secret_key
from .datalib import asdict as wgmesh_asdict, convert_uuid_uuid, emptyValuesTuple
from .datalib import message_encode, fetch_and_decode_record
from .transforms import EndpointHostRegistrationMessage


def nonone(arg):
    """eliminate the None and blanks"""
    if arg is None:
        return ""
    return arg


def convert_hostname(arg: str) -> str:
    """coerce empty strings into the hostname of localhost()"""
    if arg.strip() in emptyValuesTuple:
        return socket.gethostname()
    return arg


@define
class Endpoint:
    """dataclass for system endpoints"""

    locus: str = field()
    site_domain: str = field()
    site_pubkey: str = field()
    hostname: str = field(default="", converter=convert_hostname)
    uuid: UUID = field(default="", converter=convert_uuid_uuid)
    cmdfping: str = field(default="/usr/sbin/fping", converter=str)
    secret_key_file: str = field(default="", converter=nonone)
    public_key_file: str = field(default="", converter=nonone)
    public_iface: str = field(default="", converter=nonone)
    public_address: List[str] = field(default=[])
    trust_iface: str = field(default="", converter=nonone)
    trust_address: str = field(default="", converter=nonone)
    asn: int = field(default=-1)
    _site_key: PublicKey = field(default="")
    public_key_encoded: str = field(default="")
    _secret_key: PrivateKey = field(default="")
    _public_key: PublicKey = field(default="")

    @classmethod
    def load_endpoint_config(
        cls, source_file: TextIO, validate: bool = True, test_mode: str = ""
    ):
        """load config from file"""
        yaml = YAML(typ="rt")
        y = yaml.load(source_file)
        logger.trace(f"Local: {y}")
        ep_values = munchify(y.get("local"))
        if validate:
            site_dict = {"locus": ep_values.locus, "publickey": ep_values.site_pubkey}
            public_records = fetch_and_decode_record(ep_values.site_domain, test_mode)
            if public_records != site_dict:
                logger.error(f"Locus Mismatch: {ep_values.site_domain}")
                logger.error(f"Config: {site_dict}")
                logger.error(f"DNS: {public_records}")
                pass
        retval = cls(**ep_values)
        return retval

    def decrypt_message(self, message: str):
        """decrypt a message, return JSON payload"""
        logger.trace(f"Decrypt Message: {message}")
        logger.trace(
            f"From Site Key: {keyexport(self._site_key)} / {keyexport(self._secret_key)}"
        )
        raw_message = b64decode(message.encode("ascii"))
        box = Box(self._secret_key, self._site_key)
        payload = box.decrypt(raw_message)
        return payload

    def encrypt_message(self, message: str) -> str:
        """encrypt a message with the host public key for transmission or posting"""
        message_box = self.get_message_box(self._site_key)
        secure_message = message_box.encrypt(message.encode("ascii"))
        retval = message_encode(secure_message)
        return retval

    def export(self):
        """export local configuration for storage"""
        retval = munchify(wgmesh_asdict(self))
        retval.uuid = str(retval.uuid)
        return retval

    def get_message_box(self, publickey: PublicKey) -> Box:
        """setup an SBox for decryption
        publickey: public key from the host who encrypted the message
        """
        logger.trace(f"create encrypted with box {self.hostname} -> {publickey}")
        retval = Box(self._secret_key, publickey)
        return retval

    def open_keys(self):
        """try to unpack the keys"""
        logger.trace("open_keys begins")
        self._site_key = load_public_key(self.site_pubkey)
        with open(self.secret_key_file, "r", encoding="utf-8") as keyfile:
            self._secret_key = load_secret_key(keyfile.read())
        if self.public_key_encoded in emptyValuesTuple:
            self.public_key_encoded = keyexport(self._secret_key.public_key)
        assert self.public_key_encoded not in emptyValuesTuple

    def publish(self):
        """export local configuration for transport"""
        assert self.public_key_encoded not in emptyValuesTuple
        retval = {
            "hostname": self.hostname,
            "uuid": str(self.uuid),
            "public_key_encoded": self.public_key_encoded,
            "public_key_file": self.public_key_file,
            "private_key_file": self.secret_key_file,
            "asn": self.asn,
            "remote_addr": ",".join(self.public_address),
        }
        return munchify(retval)

    def save_endpoint_config(self):
        """return a yaml bundle for storing endpoint config"""
        yaml = YAML(typ="rt")
        buffer = StringIO()
        logger.trace("save site to yaml")
        output = {"local": unmunchify(self.export())}
        logger.debug(f"{output}")
        yaml.dump(output, buffer)
        buffer.seek(0)
        return buffer.read()

    def send_host_message(self):
        """export local configuration for transport"""
        retval = EndpointHostRegistrationMessage(**self.publish())
        return retval
