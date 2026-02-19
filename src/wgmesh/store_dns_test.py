#!/usr/bin/env python3
"""test mode DNS storage - simulates Route53 by writing to local files"""

import os
import json
from pathlib import Path

from loguru import logger
from attrs import define, field


def convert_site_domain(arg):
    """add a '.' if needed"""
    if arg[-1] != ".":
        arg += "."
    return arg


def domain_separator(hostname, domainname):
    split = hostname.find(domainname)
    uuid = hostname[:split].strip(".")
    domain = hostname[split:]
    return uuid, domain


@define
class TestDNSDataClass:
    """Simulates DNSDataClass but writes to local files for testing"""

    zoneid: str = field()
    site_domain: str = field(converter=convert_site_domain)
    access: str = field()
    secret: str = field()
    test_dir: str = field()
    site_record: str = field(default="")
    zone_domain: str = field(default="")
    records: list = field(default=[])
    maps: dict = field(default={})

    @classmethod
    def openZone(cls, zoneid, domain, access, secret, test_dir="./test_dns"):
        """create test dns storage in local directory"""
        retval = cls(zoneid, domain, access, secret, test_dir)
        retval.connect()
        return retval

    def connect(self):
        """setup test directory structure"""
        logger.info(
            f"TEST MODE: Using local directory {self.test_dir} instead of Route53"
        )
        Path(self.test_dir).mkdir(parents=True, exist_ok=True)

        # Load existing records if any
        site_file = Path(self.test_dir) / "site_record.json"
        if site_file.exists():
            with open(site_file, "r") as f:
                self.site_record = json.load(f)

        # Load host records
        self.maps = {}
        for host_file in Path(self.test_dir).glob("host_*.json"):
            uuid = host_file.stem.replace("host_", "")
            with open(host_file, "r") as f:
                self.maps[uuid] = json.load(f)

    def chunk_data(self, payload):
        """split bas64 into chunked data that will fit into dns"""
        from textwrap import wrap

        return [f'"{i}:{x}"' for i, x in enumerate(wrap(payload, width=74)) if x > ""]

    def write_site(self, payload: str) -> str:
        """write site record to local file"""
        chunked_data = self.chunk_data(payload)
        record_data = {
            "name": str(self.site_domain),
            "type": "TXT",
            "records": chunked_data,
            "raw_payload": payload,
        }

        site_file = Path(self.test_dir) / "site_record.json"
        with open(site_file, "w") as f:
            json.dump(record_data, f, indent=2)

        self.site_record = record_data
        logger.info(f"TEST MODE: Wrote site record to {site_file}")
        return f"Test mode: wrote site record ({len(payload)} bytes)"

    def write_host(self, uuid: str, payload: str) -> str:
        """write host record to local file"""
        chunked_data = self.chunk_data(payload)
        record_data = {
            "name": f"{uuid}.{self.site_domain}",
            "type": "TXT",
            "records": chunked_data,
            "uuid": uuid,
            "raw_payload": payload,
        }

        host_file = Path(self.test_dir) / f"host_{uuid}.json"
        with open(host_file, "w") as f:
            json.dump(record_data, f, indent=2)

        self.maps[uuid] = record_data
        logger.info(f"TEST MODE: Wrote host record to {host_file}")
        return f"Test mode: wrote host record {uuid} ({len(payload)} bytes)"

    def remove_host(self, uuid: str):
        """remove host record from local files"""
        host_file = Path(self.test_dir) / f"host_{uuid}.json"
        if host_file.exists():
            host_file.unlink()
            logger.info(f"TEST MODE: Removed host record {host_file}")
        if uuid in self.maps:
            del self.maps[uuid]
        return f"Test mode: removed host {uuid}"
