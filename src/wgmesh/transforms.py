#!/usr/bin/env python3
"""data and document transformation classes"""

from base64 import b64encode, b64decode
from ipaddress import ip_address

from loguru import logger
from attr import define, field, asdict
from munch import munchify, Munch
from nacl.public import Box, PublicKey, PrivateKey


from .crypto import keyexport

##
## Document transformations
##

##
# Transformations:
#
# disk -> memory
# site -> &hosts
# memory -> disk
# hosts &-> Site -> YAML
#
# site -> public DNS
# 2
#


def convert_public_key(arg):
    """convert a public key to base64 encoded"""
    ## fixme: this is backwards
    if isinstance(arg, PublicKey):
        return keyexport(arg)
    else:
        return arg


def convert_list_to_csv(arg):
    """join a list with comma's"""
    return ",".join(arg)


def convert_base64_to_bytes(arg):
    """convert a binary payload to binary"""
    return b64decode(arg)


@define
class EncryptedAWSSecrets:
    access_key: str = field()
    secret_key: str = field()

    @classmethod
    def load_encrypted_credentials(cls, payload, box):
        """load encrypted aws credentials"""
        raw_message = b64decode(payload)
        hidden_message = munchify({}).fromJSON(box.decrypt(raw_message))
        retval = EncryptedAWSSecrets(
            hidden_message.access_key, hidden_message.secret_key
        )
        return retval

    def publish(self) -> Munch:
        return munchify({"access_key": self.access_key, "secret_key": self.secret_key})

    def export_encrypted_credentials(self, box: Box):
        """self -> json -> encrypt -> str"""
        json_dump = self.publish().toJSON()
        encrypted_message = box.encrypt(json_dump.encode("ascii"))
        return b64encode(encrypted_message).decode("utf-8")


@define
class SitePublicRecord:
    locus: str = field()
    publickey: PublicKey = field(converter=convert_public_key)

    def toJSON(self):
        return munchify(asdict(self)).toJSON()

    def publish(self):
        return munchify(asdict(self))

    @classmethod
    def fromJSON(cls, jsonstring):
        """load the json string"""
        values = munchify({}).fromJSON(jsonstring)
        spr = cls(values.locus, values.publickey)
        return spr


@define
class SiteEncryptedHostRegistration:
    publickey: PublicKey = field(converter=convert_public_key)
    message: bytes = field(converter=convert_base64_to_bytes)

    @classmethod
    def from_base64_json(cls, payload):
        """decode a base64 message, and return the Encrypted Message"""
        raw_message = b64decode(payload).decode("utf-8")
        content = munchify({}).fromJSON(raw_message)
        return SiteEncryptedHostRegistration(content.publickey, content.message)

    def decrypt(self, box: Box):
        """attempt to decrypt the message"""
        hidden_message = munchify({}).fromJSON(
            box.decrypt(self.message).decode("utf-8")
        )
        logger.trace(f"Decrypted message: {hidden_message}")
        retval = HostRegistration(
            hidden_message.uuid,
            hidden_message.hostname,
            hidden_message.public_key_encoded,
            hidden_message.public_key_file,
            hidden_message.private_key_file,
        )
        retval.split_remotes(hidden_message.remote_addr)
        return retval.publish()

    def encrypt(self, box: Box):
        """attempt to decrypt the message"""
        hidden_message = munchify({}).fromJSON(
            box.decrypt(self.message).decode("utf-8")
        )
        logger.trace(f"Decrypted message: {hidden_message}")
        retval = HostRegistration(
            hidden_message.uuid,
            hidden_message.public_key,
            hidden_message.public_key_file,
        )
        retval.split_remotes(hidden_message.remote_addr)
        return retval


@define
class RemoteHostRecord:
    key: str = field()
    asn: int = field()
    hostname: str = field()
    localport: int = field()
    remoteport: int = field()
    remote: str = field()

    def export(self):
        """export a JSON ready form of this modules"""
        retval = munchify(asdict(self))
        logger.trace(retval)
        retval.remote = [str(x) for x in retval.remote]
        return retval


@define
class DeployMessage:
    asn: int = field()
    site: str = field()
    octet: int = field()
    portbase: int = field()
    remote: str = field()
    hosts: dict = field(default={})

    def publish(self):
        """publish a DeployMessage + RemoteHostRecords"""
        retval = munchify(asdict(self))
        for k, v in retval.hosts.items():
            logger.trace(f"Value: {v}")
            continue
        logger.trace(f"Publish DeployMessage: {retval}")
        return retval

    def publish_encrypted(self, box: Box):
        raw_content = self.publish().toJSON()
        raw_message = box.encrypt(raw_content.encode("ascii"))
        text_message = b64encode(raw_message).decode("utf-8")
        return text_message


@define
class EndpointHostRegistrationMessage:
    hostname: str = field()
    uuid: str = field(converter=str)
    remote_addr: str = field()
    public_key: str = field()
    public_key_file: str = field()
    private_key_file: str = field()


@define
class HostRegistration:
    uuid: str = field(converter=str)
    hostname: str = field()
    public_key_encoded: str = field()
    public_key_file: str = field()
    private_key_file: str = field()
    local_ipv4: list = field(default=[])
    local_ipv6: list = field(default=[])

    def publish(self):
        """export the local"""
        return munchify(asdict(self))

    def split_remotes(self, remote_addrs):
        """older host registrations send all remote addresses in a single list"""
        logger.debug(f"split_remotes: {self.local_ipv4}/{self.local_ipv6}")
        for x in remote_addrs.split(","):
            try:
                addr = ip_address(x)
            except ValueError:
                logger.warning(f"Ignoring invalid IP: {x}")
                continue
            if addr.version == 4:
                self.local_ipv4.append(addr)
                logger.trace(f": Host remote address: {addr}")
            elif addr.version == 6:
                self.local_ipv6.append(addr)
                logger.trace(f": Host remote address: {addr}")
            else:
                logger.error(f"Unknown Address: {x}")
                continue
            continue


@define
class EncryptedHostRegistration:
    publickey: PublicKey = field()
    privatekey: PrivateKey = field()

    def publish(self):
        """render the total payload for host registration"""
        return {}


#
# public dns -> host
# host -> site message

#
# site -> host configuration
#

#
# host -> deployment templating
#
