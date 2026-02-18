#!/usr/bin/env python3
"""tests for wgsite commands and test DNS mode"""

import os
import sys
import json
import tempfile
import shutil
from io import StringIO
from uuid import UUID, uuid4
from pathlib import Path

import pytest
from munch import munchify

from wgmesh.lib import LoggerConfig
from wgmesh.crypto import generate_key, keyexport, load_public_key, load_secret_key
from wgmesh.sitedata import Site
from wgmesh.store_dns_test import TestDNSDataClass
from wgmesh.transforms import SiteEncryptedHostRegistration, HostRegistration

# Initialize logging
LoggerConfig(True, False)

# Test data
test_site_config = """
global:
  locus: testmesh
  domain: test.example.com
  asn_range: 64512:64520
  portbase: 21100
  tunnel_ipv6: fd86:ea04:1116::/64
  tunnel_ipv4: 192.0.2.0/24
  publickey: {publickey}
  privatekey: {privatekey_path}
  route53: Z1TESTZONE
  aws_access_key: test_access_key
  aws_secret_access_key: test_secret_key
hosts: {{}}
"""

test_host_data = {
    "uuid": "7bc1bafe-87ba-4471-9ea7-6ef8e99b82c0",
    "hostname": "testhost.example.com",
    "public_key_encoded": "8BanecEAEKcByL4BDslkHNfPXiiljOgfd68g4A/cJlQ=",
    "local_ipv4": ["10.0.0.1"],
    "local_ipv6": [],
    "local_networks": "",
}


@pytest.fixture
def temp_site(tmp_path):
    """Create a temporary site configuration for testing"""
    # Generate test keys
    private_key = generate_key()
    public_key = private_key.public_key

    privatekey_path = tmp_path / "test_priv"
    publickey_path = tmp_path / "test_pub"

    # Save keys
    with open(privatekey_path, "w") as f:
        f.write(keyexport(private_key))
    with open(publickey_path, "w") as f:
        f.write(keyexport(public_key))

    # Create site config
    config_content = test_site_config.format(
        privatekey_path=str(privatekey_path), publickey=keyexport(public_key)
    )
    config_path = tmp_path / "testmesh.yaml"
    with open(config_path, "w") as f:
        f.write(config_content)

    return {
        "tmp_path": tmp_path,
        "config_path": str(config_path),
        "private_key": private_key,
        "public_key": public_key,
        "privatekey_path": str(privatekey_path),
        "publickey_path": str(publickey_path),
    }


@pytest.fixture
def test_dns_dir(tmp_path):
    """Create a temporary directory for test DNS storage"""
    dns_dir = tmp_path / "test_dns"
    dns_dir.mkdir()
    return str(dns_dir)


class TestTestDNSDataClass:
    """Tests for the TestDNSDataClass (simulated Route53)"""

    def test_dns_creation(self, test_dns_dir):
        """Test creating a TestDNSDataClass instance"""
        dns = TestDNSDataClass.openZone(
            zoneid="Z1TESTZONE",
            domain="test.example.com",
            access="test_access",
            secret="test_secret",
            test_dir=test_dns_dir,
        )

        assert dns is not None
        assert dns.zoneid == "Z1TESTZONE"
        assert dns.site_domain == "test.example.com."
        assert os.path.exists(test_dns_dir)

    def test_write_site_record(self, test_dns_dir):
        """Test writing a site record to simulated DNS"""
        dns = TestDNSDataClass.openZone(
            zoneid="Z1TESTZONE",
            domain="test.example.com",
            access="test_access",
            secret="test_secret",
            test_dir=test_dns_dir,
        )

        test_payload = '{"locus": "testmesh", "publickey": "test123"}'
        result = dns.write_site(test_payload)

        # Check that the file was created
        site_file = Path(test_dns_dir) / "site_record.json"
        assert site_file.exists()

        # Check content
        with open(site_file, "r") as f:
            data = json.load(f)
            assert data["type"] == "TXT"
            assert data["name"] == "test.example.com."
            assert data["raw_payload"] == test_payload

    def test_write_host_record(self, test_dns_dir):
        """Test writing a host record to simulated DNS"""
        dns = TestDNSDataClass.openZone(
            zoneid="Z1TESTZONE",
            domain="test.example.com",
            access="test_access",
            secret="test_secret",
            test_dir=test_dns_dir,
        )

        host_uuid = "7bc1bafe-87ba-4471-9ea7-6ef8e99b82c0"
        test_payload = "encrypted_host_data_here"
        result = dns.write_host(host_uuid, test_payload)

        # Check that the file was created
        host_file = Path(test_dns_dir) / f"host_{host_uuid}.json"
        assert host_file.exists()

        # Check content
        with open(host_file, "r") as f:
            data = json.load(f)
            assert data["type"] == "TXT"
            assert data["uuid"] == host_uuid
            assert data["raw_payload"] == test_payload

    def test_remove_host_record(self, test_dns_dir):
        """Test removing a host record from simulated DNS"""
        dns = TestDNSDataClass.openZone(
            zoneid="Z1TESTZONE",
            domain="test.example.com",
            access="test_access",
            secret="test_secret",
            test_dir=test_dns_dir,
        )

        host_uuid = "7bc1bafe-87ba-4471-9ea7-6ef8e99b82c0"
        dns.write_host(host_uuid, "test_payload")

        # Verify it exists
        host_file = Path(test_dns_dir) / f"host_{host_uuid}.json"
        assert host_file.exists()

        # Remove it
        dns.remove_host(host_uuid)

        # Verify it's gone
        assert not host_file.exists()
        assert host_uuid not in dns.maps


class TestWgsiteIntegration:
    """Integration tests for wgsite commands with simulated DNS"""

    def test_site_load_and_publish(self, temp_site, test_dns_dir):
        """Test loading a site and publishing to simulated DNS"""
        # Load site
        with open(temp_site["config_path"], "r") as cf:
            site = Site(cf)

        # Create test DNS
        dns = TestDNSDataClass.openZone(
            zoneid=site.site.route53,
            domain=site.site.domain,
            access=site.site.aws_access_key,
            secret=site.site.aws_secret_access_key,
            test_dir=test_dns_dir,
        )

        # Create public payload
        public_message = site.site.publish_public_payload()
        assert "locus" in public_message
        assert public_message["locus"] == "testmesh"

        # Write to simulated DNS
        from wgmesh.lib import create_public_txt_record

        txt_record = create_public_txt_record(public_message)
        dns.write_site(txt_record)

        # Verify it was written
        site_file = Path(test_dns_dir) / "site_record.json"
        assert site_file.exists()

    def test_add_host_and_publish(self, temp_site, test_dns_dir):
        """Test adding a host to a site and publishing"""
        # Load site
        with open(temp_site["config_path"], "r") as cf:
            site = Site(cf)

        # Create a host signup message
        host_uuid = uuid4()
        host_key = generate_key()

        # Get site's public key for encryption
        site_public_key = load_public_key(site.site.publickey)

        # Create host signup
        signup_data = {
            "uuid": str(host_uuid),
            "hostname": "newhost.example.com",
            "public_key_encoded": keyexport(host_key.public_key),
            "local_ipv4": ["10.0.1.1"],
            "local_ipv6": [],
        }

        # Add host to site
        site.host_add(munchify(signup_data))

        # Verify host was added
        added_host = site.get_host_by_uuid(host_uuid)
        assert added_host is not None
        assert added_host.hostname == "newhost.example.com"

        # Save the updated site config
        updated_config = site.save_site_config()
        assert "newhost.example.com" in updated_config

        # Publish to test DNS
        dns = TestDNSDataClass.openZone(
            zoneid=site.site.route53,
            domain=site.site.domain,
            access=site.site.aws_access_key,
            secret=site.site.aws_secret_access_key,
            test_dir=test_dns_dir,
        )

        # Write site record
        public_message = site.site.publish_public_payload()
        from wgmesh.lib import create_public_txt_record

        dns.write_site(create_public_txt_record(public_message))

        # Write host record (encrypted)
        from wgmesh.transforms import DeployMessage, RemoteHostRecord

        deploy_message = DeployMessage(
            asn=added_host.asn,
            site=site.site.domain,
            octet=added_host.octet,
            portbase=site.site.portbase,
            remote=str(site.site.tunnel_ipv6),
        )

        message_box = site.get_site_message_box(host_key.public_key)
        encrypted_message = deploy_message.publish_encrypted(message_box)
        dns.write_host(str(host_uuid), encrypted_message)

        # Verify files were created
        assert (Path(test_dns_dir) / "site_record.json").exists()
        assert (Path(test_dns_dir) / f"host_{host_uuid}.json").exists()

    def test_delete_host_and_publish(self, temp_site, test_dns_dir):
        """Test deleting a host and publishing updated DNS"""
        # Load site
        with open(temp_site["config_path"], "r") as cf:
            site = Site(cf)

        # Add a host first
        host_uuid = uuid4()
        host_data = munchify(
            {
                "uuid": str(host_uuid),
                "hostname": "host-to-delete.example.com",
                "public_key_encoded": keyexport(generate_key().public_key),
                "local_ipv4": ["10.0.2.1"],
            }
        )
        site.host_add(host_data)

        # Verify host exists
        assert site.get_host_by_uuid(host_uuid) is not None

        # Delete the host
        site.host_delete(host_uuid)

        # Verify host was deleted
        assert site.get_host_by_uuid(host_uuid) is None

        # Publish to test DNS
        dns = TestDNSDataClass.openZone(
            zoneid=site.site.route53,
            domain=site.site.domain,
            access=site.site.aws_access_key,
            secret=site.site.aws_secret_access_key,
            test_dir=test_dns_dir,
        )

        # Write updated site record
        public_message = site.site.publish_public_payload()
        from wgmesh.lib import create_public_txt_record

        dns.write_site(create_public_txt_record(public_message))

        # Try to remove host record (it shouldn't exist but test the path)
        try:
            dns.remove_host(str(host_uuid))
        except KeyError:
            pass  # Expected if host wasn't in DNS

        # Verify site record was written
        assert (Path(test_dns_dir) / "site_record.json").exists()

    def test_multiple_hosts_publish(self, temp_site, test_dns_dir):
        """Test adding multiple hosts and publishing all"""
        # Load site
        with open(temp_site["config_path"], "r") as cf:
            site = Site(cf)

        # Add multiple hosts
        hosts = []
        for i in range(3):
            host_uuid = uuid4()
            host_key = generate_key()
            host_data = munchify(
                {
                    "uuid": str(host_uuid),
                    "hostname": f"host{i}.example.com",
                    "public_key_encoded": keyexport(host_key.public_key),
                    "local_ipv4": [f"10.0.{i}.1"],
                }
            )
            site.host_add(host_data)
            hosts.append({"uuid": host_uuid, "key": host_key, "data": host_data})

        # Verify all hosts were added
        assert len(site.hosts) == 3

        # Publish to test DNS
        dns = TestDNSDataClass.openZone(
            zoneid=site.site.route53,
            domain=site.site.domain,
            access=site.site.aws_access_key,
            secret=site.site.aws_secret_access_key,
            test_dir=test_dns_dir,
        )

        # Write site record
        public_message = site.site.publish_public_payload()
        from wgmesh.lib import create_public_txt_record

        dns.write_site(create_public_txt_record(public_message))

        # Write all host records
        from wgmesh.transforms import DeployMessage

        for host_info in hosts:
            host = site.get_host_by_uuid(host_info["uuid"])
            deploy_message = DeployMessage(
                asn=host.asn,
                site=site.site.domain,
                octet=host.octet,
                portbase=site.site.portbase,
                remote=str(site.site.tunnel_ipv6),
            )

            message_box = site.get_site_message_box(host_info["key"].public_key)
            encrypted_message = deploy_message.publish_encrypted(message_box)
            dns.write_host(str(host_info["uuid"]), encrypted_message)

        # Verify all files were created
        assert (Path(test_dns_dir) / "site_record.json").exists()
        for host_info in hosts:
            assert (Path(test_dns_dir) / f"host_{host_info['uuid']}.json").exists()

        # Verify maps contains all hosts
        assert len(dns.maps) == 3
