#!/usr/bin/env python3
"""wgmesh site-specific operations"""

# Create the host basics locally
import os
import sys
import typer
from uuid import UUID
from typing import Annotated

from loguru import logger
from munch import munchify

from .lib import create_public_txt_record, domain_report
from .lib import site_report, filediff
from .lib import InvalidHostName, InvalidMessage
from .lib import LoggerConfig
from .datalib import fetch_and_decode_record

from .transforms import SiteEncryptedHostRegistration, RemoteHostRecord, DeployMessage

from .crypto import generate_site_key, load_public_key, load_secret_key, keyexport
from .store_dns import DNSDataClass
from .store_dns_test import TestDNSDataClass
from .sitedata import Site

app = typer.Typer()


@app.command()
def init(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    domain: Annotated[
        str,
        typer.Argument(
            help="primary domain where the locus TXT record will be published."
        ),
    ],
    asn: Annotated[
        str, typer.Argument(help="Range of ASN Number (32bit ok) ex. 64512:64550")
    ],
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    secret_key_file: Annotated[str, typer.Option(help="secret key filename.")] = "",
    tunnel_ipv6: Annotated[
        str, typer.Option(help="/64 ipv6 network block for tunnel routing")
    ] = "",
    tunnel_ipv4: Annotated[
        str, typer.Option(help="/64 ipv6 network block for tunnel routing")
    ] = "",
    portbase: Annotated[
        int, typer.Option(help="Starting Point for inter-system tunnel connections.")
    ] = 0,
    aws_zone: Annotated[str, typer.Option(help="AWS Route53 Records Zone.")] = "",
    aws_access: Annotated[
        str, typer.Option(envvar="AWS_ACCESS_KEY", help="AWS Access Key")
    ] = "",
    aws_secret: Annotated[
        str, typer.Option(envvar="AWS_SECRET_KEY", help="AWS Secret Key")
    ] = "",
    suggest: Annotated[bool, typer.Option(help="Auto suggest tunnel networks")] = False,
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """
    generate initial host configuration

    requires: locus (matches familiar site),
              domainname (TXT record published by site master),
              ASN Range (BGP range for mesh instances)
    """
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f"{locus}.yaml")

    if os.path.exists(config_file) and not force and not dryrun:
        logger.error(
            f"Error: {config_file} exists. Aborting. (use --force to overwrite)"
        )
        sys.exit(1)

    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as cf:
            old_data = cf.read()
            pass
    else:
        old_data = ""
        pass

    if not secret_key_file:
        secret_path = os.path.join(config_path, f"{locus}_priv")
        logger.debug(f": {secret_key_file}")
    else:
        secret_path = secret_key_file
        pass
    if os.path.exists(secret_path):
        with open(secret_path, "r", encoding="utf-8") as keyfile:
            secret_key = load_secret_key(keyfile.read())
    else:
        secret_key = generate_site_key(secret_path, dryrun)
        if dryrun:
            print(f"Generated key (discarding): {keyexport(secret_key)}")

    arguments = munchify(
        {"locus": locus, "domain": domain, "asn_range": asn, "privatekey": secret_path}
    )

    if tunnel_ipv6:
        arguments.tunnel_ipv6 = tunnel_ipv6
    elif suggest:
        arguments.tunnel_ipv6 = "fd86:ea04:1116::/64"
        pass

    if tunnel_ipv4:
        arguments.tunnel_ipv4 = tunnel_ipv4
    elif suggest:
        arguments.tunnel_ipv4 = "192.0.2.0/24"
        pass

    if portbase:
        arguments.portbase = portbase
    elif suggest:
        arguments.portbase = 9000
        pass

    if aws_zone and aws_access and aws_secret:
        arguments.route53 = aws_zone
        arguments.aws_access_key = aws_access
        arguments.aws_secret_access_key = aws_secret
        pass

    site = Site(sitecfg_args=arguments)
    save_data = site.save_site_config()
    print(filediff(old_data, save_data, f"{config_file}.old", config_file))

    if dryrun:
        print("dryrun, no changes saved")
    else:
        with open(config_file, "w", encoding="utf-8") as cf:
            cf.write(save_data)
            pass
        pass
    site_report(locus, site.publish())
    print("New mesh created")
    print(f"Now, you can run 'wgsite publish {site.site.locus}'")
    return 0


@app.command()
def wizard(
    locus: Annotated[
        str, typer.Option(help="short/familiar name, short hand for this mesh")
    ] = "",
    domain: Annotated[
        str,
        typer.Option(
            help="primary domain where the locus TXT record will be published."
        ),
    ] = "",
    asn: Annotated[
        str, typer.Option(help="Range of ASN Number (32bit ok) ex. 64512:64550")
    ] = "",
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    tunnel_ipv6: Annotated[
        str, typer.Option(help="/64 ipv6 network block for tunnel routing")
    ] = "",
    tunnel_ipv4: Annotated[
        str, typer.Option(help="ipv4 network block for tunnel routing")
    ] = "",
    portbase: Annotated[
        int, typer.Option(help="Starting Point for inter-system tunnel connections.")
    ] = 0,
    aws_zone: Annotated[str, typer.Option(help="AWS Route53 Records Zone.")] = "",
    aws_access: Annotated[
        str, typer.Option(envvar="AWS_ACCESS_KEY", help="AWS Access Key")
    ] = "",
    aws_secret: Annotated[
        str, typer.Option(envvar="AWS_SECRET_KEY", help="AWS Secret Key")
    ] = "",
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """builds a new site config from prompts (defaults in wgmesh-default.yaml)"""
    LoggerConfig(debug, trace)

    print("=== wgmesh Site Configuration Wizard ===")
    print("")

    if locus:
        print(f"Site locus: {locus}")
    else:
        locus = typer.prompt("Site locus (short name for this mesh)")

    if domain:
        print(f"Primary domain: {domain}")
    else:
        domain = typer.prompt("Primary domain for TXT records")

    if asn:
        print(f"ASN Range: {asn}")
    else:
        asn = typer.prompt("ASN Range (e.g., 64512:64550)", default="64512:64550")

    if tunnel_ipv6:
        print(f"IPv6 tunnel network: {tunnel_ipv6}")
    else:
        tunnel_ipv6 = typer.prompt(
            "IPv6 tunnel network (/64)", default="fd86:ea04:1116::/64"
        )

    if tunnel_ipv4:
        print(f"IPv4 tunnel network: {tunnel_ipv4}")
    else:
        tunnel_ipv4 = typer.prompt("IPv4 tunnel network", default="192.0.2.0/24")

    if portbase:
        print(f"Port base: {portbase}")
    else:
        portbase = typer.prompt("Port base for tunnels", default=9000, type=int)

    if aws_zone:
        print(f"AWS Route53 Zone: {aws_zone}")
        use_aws = True
    elif aws_access or aws_secret:
        use_aws = True
    else:
        use_aws = typer.confirm("Configure AWS Route53?", default=True)

    if use_aws:
        if not aws_zone:
            aws_zone = typer.prompt("Route53 Zone ID")
        if not aws_access:
            aws_access = typer.prompt("AWS Access Key")
        if not aws_secret:
            aws_secret = typer.prompt("AWS Secret Key", hide_input=True)
    else:
        aws_zone = ""
        aws_access = ""
        aws_secret = ""

    config_file = os.path.join(config_path, f"{locus}.yaml")

    if os.path.exists(config_file) and not force and not dryrun:
        logger.error(
            f"Error: {config_file} exists. Aborting. (use --force to overwrite)"
        )
        sys.exit(1)

    # Create config directory if it doesn't exist
    if not dryrun and not os.path.exists(config_path):
        logger.info(f"Creating config directory: {config_path}")
        os.makedirs(config_path, exist_ok=True)

    # Generate or use existing key
    secret_path = os.path.join(config_path, f"{locus}_priv")
    if os.path.exists(secret_path):
        logger.info(f"Using existing key: {secret_path}")
        with open(secret_path, "r", encoding="utf-8") as keyfile:
            secret_key = load_secret_key(keyfile.read())
    else:
        secret_key = generate_site_key(secret_path, dryrun)
        if dryrun:
            print(f"Generated key (discarding): {keyexport(secret_key)}")

    arguments = munchify(
        {
            "locus": locus,
            "domain": domain,
            "asn_range": asn,
            "privatekey": secret_path,
            "tunnel_ipv6": tunnel_ipv6,
            "tunnel_ipv4": tunnel_ipv4,
            "portbase": portbase,
        }
    )

    if use_aws and aws_zone and aws_access and aws_secret:
        arguments.route53 = aws_zone
        arguments.aws_access_key = aws_access
        arguments.aws_secret_access_key = aws_secret

    site = Site(sitecfg_args=arguments)
    save_data = site.save_site_config()

    print("")
    print("=== Configuration Summary ===")
    site_report(locus, site.publish())

    if dryrun:
        print("\ndryrun mode, no changes saved")
    else:
        with open(config_file, "w", encoding="utf-8") as cf:
            cf.write(save_data)
        print(f"\nConfiguration saved to: {config_file}")
        print(f"Now, you can run 'wgsite publish {site.site.locus}'")

    return 0


@app.command()
def check(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    test_mode: Annotated[
        str,
        typer.Option(
            help="Test mode: read DNS records from local folder for validation"
        ),
    ] = "",
    verbose: Annotated[bool, typer.Option(help="Add verbosity")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """check config, publish site report"""
    LoggerConfig(debug, trace)

    if locus[-4:] in ["yaml"]:
        logger.warning("Removing '.yaml' from locus name.")
        locus = locus[:-5]
    config_file = os.path.join(config_path, f"{locus}.yaml")
    with open(config_file, "r", encoding="utf-8") as cf:
        site = Site(cf)

    site_report(locus, site.publish())

    if test_mode:
        logger.info(f"TEST MODE: Reading DNS from {test_mode}")
        _domain_report_test_mode(site, test_mode)
    else:
        domain_report(site.site)
    print("")

    for me in site.hosts:
        myport = me.endport()
        deploy_message = DeployMessage(
            asn=me.asn,
            site=site.site.domain,
            octet=me.octet,
            portbase=site.site.portbase,
            remote=site.site.tunnel_ipv6,
        )
        print(f"Deploy Host Check: {me.hostname}/{str(me.uuid)}")
        if me.asn == -1:
            print("-! Skipping Host (No ASN)")
            print("")
            continue
        if me.public_key_encoded == "":
            print("-! Skipping Host (No Public Key)")
            print("")
            continue
        print(
            f"-> Port: {myport} | ASN: {me.asn} | Public Key: {me.public_key_encoded}"
        )
        if verbose:
            print(f"-> DM: {deploy_message}")
        print(f"-> RHR Checks:")
        for host in site.hosts:
            if host.uuid == me.uuid:
                continue
            if host.asn == -1:
                print(f"    -> Skipping Host: {host.hostname} - (no ASN)")
                continue
            if host.public_key_encoded == "":
                print(f"    -> Skipping Host: {host.hostname} - (no PublicKey)")
                continue
            host_record = RemoteHostRecord(
                key=host.public_key_encoded,
                hostname=host.hostname,
                asn=host.asn,
                localport=host.endport(),
                remoteport=myport,
                remote=host.endpoint_addresses(),
            )
            print(
                f"    -> Host: {host.hostname} | ASN: {host.asn} | UUID: {str(host.uuid)} | {host.public_key_encoded} | RHR Ok."
            )
            if verbose:
                print(f"    -> RHR: {host_record.export()}")
            continue
        print(f"-> Site Configuration Package Complete")
        print("")
        continue
    return 0


def _domain_report_test_mode(site: Site, test_dir: str):
    """Display domain report using test DNS storage"""
    from pathlib import Path
    import json

    # Load test DNS data
    site_file = Path(test_dir) / "site_record.json"

    existing_records = None
    if site_file.exists():
        with open(site_file, "r") as f:
            data = json.load(f)
            # Parse the chunked payload
            raw_payload = data.get("raw_payload", "")
            try:
                from .datalib import decode_domain

                existing_records = decode_domain(raw_payload)
            except Exception as e:
                logger.warning(f"Test DNS holds invalid data: {e}")
                existing_records = "[Invalid data]"

    dns_payload = site.site.publish_public_payload()

    print()
    print("DNS CHECK (TEST MODE):")
    if existing_records:
        if existing_records == dns_payload:
            print("  DNS CHECK: Passed")
        else:
            print("  DNS CHECK: Failed")
        print(f"  - Calculated: {dns_payload}")
        print(f"  - Published (test): {existing_records}")
    else:
        print("  No DNS records found in test directory")


@app.command()
def setsite(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    domain: Annotated[
        str,
        typer.Option(
            help="primary domain where the locus TXT record will be published."
        ),
    ] = "",
    asn: Annotated[
        str, typer.Option(help="Range of ASN Number (32bit ok) ex. 64512:64550")
    ] = "",
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    secret_key_file: Annotated[str, typer.Option(help="secret key filename.")] = "",
    tunnel_ipv6: Annotated[
        str, typer.Option(help="/64 ipv6 network block for tunnel routing")
    ] = "",
    tunnel_ipv4: Annotated[
        str, typer.Option(help="/64 ipv6 network block for tunnel routing")
    ] = "",
    portbase: Annotated[
        int, typer.Option(help="Starting Point for inter-system tunnel connections.")
    ] = 0,
    aws_zone: Annotated[str, typer.Option(help="AWS Route53 Records Zone.")] = "",
    aws_access: Annotated[
        str, typer.Option(envvar="AWS_ACCESS_KEY", help="AWS Access Key")
    ] = "",
    aws_secret: Annotated[
        str, typer.Option(envvar="AWS_SECRET_KEY", help="AWS Secret Key")
    ] = "",
    suggest: Annotated[bool, typer.Option(help="Auto suggest tunnel networks")] = False,
    asnfix: Annotated[
        bool, typer.Option(help="Update ASNs, supply any which are empty.")
    ] = False,
    reset_aws: Annotated[
        bool, typer.Option(help="Reset AWS credentials (prompts for new keys)")
    ] = False,
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """(re)configure site settings"""
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f"{locus}.yaml")

    with open(config_file, "r", encoding="utf-8") as cf:
        site = Site(cf)
        pass
    previous = site.save_site_config()

    update = (
        "domain",
        "secret_key_file",
        "tunnel_ipv6",
        "tunnel_ipv4",
        "portbase",
    )

    for x in update:
        val = locals().get(x)
        if val:
            logger.trace(f"Update Site Setting: {x} => {val}")
            setattr(site.site, x, val)
            continue
        continue

    if asn:
        ## fixup asn range
        site.site.asn_range = asn

    if (aws_zone or site.site.route53) and aws_access and aws_secret:
        logger.debug("Set AWS Credentials")
        if aws_zone:
            logger.trace(f"AWS Zone Changed: {site.site.route53} => {aws_zone}")
            site.site.route53 = aws_zone
        site.site.aws_access_key = aws_access
        site.site.aws_secret_access_key = aws_secret
        site.site.update_aws_credentials(aws_access, aws_secret)
        pass

    if reset_aws:
        print("\n=== Reset AWS Credentials ===")
        aws_access = typer.prompt("AWS Access Key")
        aws_secret = typer.prompt("AWS Secret Key", hide_input=True)
        logger.debug("Set AWS Credentials")
        site.site.aws_access_key = aws_access
        site.site.aws_secret_access_key = aws_secret
        site.site.update_aws_credentials(aws_access, aws_secret)
        pass

    if asnfix:
        site.check_asn_sanity()

    save_data = site.save_site_config()
    diff = filediff(previous, save_data, f"{config_file}.old", config_file)
    print(diff)

    # site_report(locus, site.publish())
    with open(config_file, "w", encoding="utf-8") as cf:
        cf.write(save_data)
    return 0


@app.command()
def genkeys(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    force: Annotated[
        bool, typer.Option(help="overwrite existing key(s). NO TAKE BACKS")
    ] = False,
):
    """generate new site key"""
    config_file = os.path.join(config_path, f"{locus}.yaml")
    with open(config_file, "r", encoding="utf-8") as cf:
        site = Site(cf)
        pass
    if os.path.exists(site.site.privatekey) and not force:
        print(
            f"Key already exists: {site.site.privatekey}. Use --force to overwrite it."
        )
        sys.exit(4)

    key = generate_site_key(site.site.privatekey, False)

    print("Key overwritten, good luck")
    return 0


@app.command()
def publish(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    aws_zone: Annotated[str, typer.Option(help="AWS Route53 Records Zone.")] = "",
    aws_access: Annotated[
        str, typer.Option(envvar="AWS_ACCESS_KEY", help="AWS Access Key")
    ] = "",
    aws_secret: Annotated[
        str, typer.Option(envvar="AWS_SECRET_KEY", help="AWS Secret Key")
    ] = "",
    test_mode: Annotated[
        str,
        typer.Option(
            help="Test mode: write DNS records to local folder instead of Route53"
        ),
    ] = "",
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """publish site and host records to dns"""
    LoggerConfig(debug, trace)

    if dryrun:
        commit = False
    else:
        commit = True
    config_file = os.path.join(config_path, f"{locus}.yaml")

    if aws_zone:
        logger.warning(f"overriding DNS zone, forcing {aws_zone}")
        pass

    with open(config_file, "r", encoding="utf-8") as cf:
        site = Site(cf)

    current_records = None
    try:
        current_records = fetch_and_decode_record(site.site.domain)
    except InvalidHostName:
        logger.debug(f"No records found for {site.site.domain}")
    except InvalidMessage:
        logger.warning(f"Invalid JSON Payload for {site.site.domain}")

    public_message = site.site.publish_public_payload()

    if public_message == current_records:
        print("DNS Correct")
    else:
        print("DNS Needs to be Updated")
        site_report(locus, site.publish())
        domain_report(site.site)

    new_txt_record = create_public_txt_record(public_message)

    logger.info("Refreshing Records")
    if aws_zone and aws_access and aws_secret:
        logger.debug("CLI-override for AWS Zone and Credentials")
        zone_name = aws_zone
        access_key = aws_access
        secret_key = aws_secret
    else:
        logger.debug("Using configured AWS Zone and Credentials")
        zone_name = site.site.route53
        access_key = site.site.aws_access_key
        secret_key = site.site.aws_secret_access_key
        pass

    # Use test mode if specified
    if test_mode:
        logger.info(f"Running in TEST MODE - writing to: {test_mode}")
        dns = TestDNSDataClass.openZone(
            zone_name, site.site.domain, access_key, secret_key, test_mode
        )
    else:
        dns = DNSDataClass.openZone(zone_name, site.site.domain, access_key, secret_key)

    logger.trace(f"Commit Record: {new_txt_record}")
    dns.write_site(new_txt_record)

    for me in site.hosts:
        if me.asn == -1:
            logger.error(
                f"{me.hostname}/({str(me.uuid)} is missing a valid ASN, skipping Deployment Publishing"
            )
            continue
        if me.public_key_encoded == "":
            logger.error(f"{me.hostname}/{str(me.uuid)} is missing a Public Key")
            continue
        myport = me.endport()
        myuuid = str(me.uuid)
        logger.trace(f"Convert PublicKey: {me.public_key_encoded}")
        public_key = load_public_key(me.public_key_encoded)
        logger.trace(f"Assemble Deployment for Host: {me.hostname}/({str(me.uuid)})")
        deploy_message = DeployMessage(
            asn=me.asn,
            site=site.site.domain,
            octet=me.octet,
            portbase=site.site.portbase,
            remote=str(site.site.tunnel_ipv6),
        )
        for host in site.hosts:
            if host.uuid == me.uuid:
                continue
            if host.asn == -1:
                logger.warning(
                    f"{me.hostname}/({myuuid} is missing a valid ASN, skipping this Mesh Inclusion"
                )
                continue
            if not host.public_key_encoded:
                logger.warning(
                    f"{me.hostname}/({myuuid} is missing a public key, skipping this Mesh Inclusion"
                )
                continue
            host_record = RemoteHostRecord(
                key=host.public_key_encoded,
                hostname=host.hostname,
                asn=host.asn,
                localport=host.endport(),
                remoteport=myport,
                remote=host.endpoint_addresses(),
            )
            logger.trace(f" - Add Mesh Host: {host.hostname}/({str(host.uuid)})")
            deploy_message.hosts[str(host.uuid)] = host_record.export()
            continue
        ## deploy_message should be a complete mesh deployment record.
        logger.trace("Publish Deployer Record:")
        message_box = site.get_site_message_box(public_key)
        encrypted_deploy_message = deploy_message.publish_encrypted(message_box)
        logger.trace(f"Encrypt and Package: {deploy_message.publish()}")
        logger.debug(f"Package DNS Record {len(encrypted_deploy_message)} bytes")
        dns.write_host(myuuid, encrypted_deploy_message)
    return 0


t = "\t"


@app.command()
def hosts(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    uuid: Annotated[
        str, typer.Argument(help="Host import string, or file with the message packet.")
    ] = None,
    names: Annotated[bool, typer.Option(help="Only list names and UUIDs")] = False,
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    test_mode: Annotated[
        str, typer.Option(help="Test mode: read DNS records from local folder")
    ] = "",
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """shows a list of hosts"""
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f"{locus}.yaml")

    with open(config_file, encoding="utf-8") as cf:
        site = Site(cf)
        pass

    logger.info("Refreshing Records")

    dns = None
    if test_mode:
        logger.info(f"TEST MODE: Reading from {test_mode}")
        dns = TestDNSDataClass.openZone(
            site.site.route53,
            site.site.domain,
            site.site.aws_access_key,
            site.site.aws_secret_access_key,
            test_mode,
        )
    elif site.site.aws_credentials:
        logger.debug("Using configured AWS Zone and Credentials")
        zone_name = site.site.route53
        access_key = site.site.aws_access_key
        secret_key = site.site.aws_secret_access_key
        dns = DNSDataClass.openZone(zone_name, site.site.domain, access_key, secret_key)

    if names:
        for x in site.hosts:
            print(f"{x.uuid}{t}{x.hostname}")
            continue
    else:
        for x in site.hosts:
            print(f"Host: {x.hostname}")
            print(f"   UUID: {x.uuid}")
            print(
                f"   ASN:{x.asn} Octet:=>[{site.site.portbase + x.octet}] [{x.octet}]"
            )
            print(f"   Address_v4:{x.local_ipv4}")
            print(f"   Address_v6:{x.local_ipv6}")
            if dns and dns.maps.get(str(x.uuid)):
                print(f"   Route 53 DNS: *PRESENT* {str(x.uuid)}")
            continue
    pass


@app.command(name="del")
def del_host(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    uuid: Annotated[str, typer.Argument(help="Host UUID to remove")],
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """removes a host from the site"""
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f"{locus}.yaml")

    with open(config_file, encoding="utf-8") as cf:
        site = Site(cf)

    old_data = site.save_site_config()
    uuid_uuid = UUID(uuid)
    site.host_delete(uuid_uuid)
    save_data = site.save_site_config()
    diff = filediff(old_data, save_data, f"{config_file}.old", config_file)
    print(diff)

    if dryrun:
        sys.exit(1)
    with open(config_file, "w", encoding="utf-8") as cf:
        cf.write(save_data)
        pass
    return 0


@app.command()
def add(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    host_message: Annotated[
        str, typer.Argument(help="Host import string, or file with the message packet.")
    ],
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    force: Annotated[bool, typer.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, typer.Option(help="do not write anything")] = False,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """adds a new host (requires a signup message or prompts for it)"""
    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f"{locus}.yaml")

    with open(config_file, encoding="utf-8") as cf:
        site = Site(cf)

    old_data = site.save_site_config()
    if os.path.exists(host_message):
        logger.debug(f"{host_message} is a file.")
        with open(host_message, "r", encoding="utf-8") as msg:
            message = msg.read()
    else:
        logger.debug("Message supplied through command line")
        message = host_message
        pass

    message = "".join([ x for x in message.split('\n') if x.strip()[0] != '#'])

    logger.warning("Unlock Message")
    logger.debug("transform stage 1, decode")
    logger.trace(f"raw message: {message}")
    encrypted_record = SiteEncryptedHostRegistration.from_base64_json(message)
    logger.trace(f"(Decoded Message: {encrypted_record}")

    logger.debug("transform stage 2, decrypt")
    decryption_box = site.get_site_message_box(encrypted_record.publickey)
    host_record = encrypted_record.decrypt(decryption_box)
    logger.trace(f"decrypted host record: {host_record}")

    logger.warning("Import Decrypted Host")
    ## override for old system
    if host_record.get("publickey"):
        logger.info(f"old host message: publickey -> public_key")
        host_record["public_key"] = host_record["publickey"]

    ## lookup existing, if it's an update
    host = site.get_host_by_uuid(host_record.uuid)
    if host:
        logger.debug(f"located existing host: {host}")
        pass

    # Compile to internal site document
    logger.debug(f"transform stage 4, Host Record: {host}")

    if host:
        logger.debug(f"Update host {host.uuid}/{host.hostname}")
        host.update(host)
    else:
        site.host_add(host_record)
        pass

    save_data = site.save_site_config()
    print(filediff(old_data, save_data, f"{config_file}.old", config_file))

    if dryrun:
        print("dryrun mode, no changes written")
    else:
        logger.trace(f"Save site: {site}")
        site_yaml = site.save_site_config()
        with open(config_file, "w", encoding="utf-8") as cf:
            cf.write(site_yaml)

    return 0


@app.command()
def dnstest(
    locus: Annotated[
        str, typer.Argument(help="short/familiar name, short hand for this mesh")
    ],
    name: Annotated[
        str,
        typer.Option(help="Record name prefix (e.g., 'test' becomes test.domain.com)"),
    ] = "test",
    content: Annotated[str, typer.Option(help="TXT record content")] = "TEST TEXT",
    config_path: Annotated[str, typer.Option(envvar="WGM_CONFIG")] = "/etc/wireguard",
    ttl: Annotated[int, typer.Option(help="DNS record TTL in seconds")] = 300,
    debug: Annotated[bool, typer.Option(help="debug logging")] = False,
    trace: Annotated[bool, typer.Option(help="trace logging")] = False,
):
    """Create a test DNS TXT record (e.g., test.feb17.wgmesh.ashbyte.com)"""
    import time
    import dns.resolver

    LoggerConfig(debug, trace)
    config_file = os.path.join(config_path, f"{locus}.yaml")

    with open(config_file, encoding="utf-8") as cf:
        site = Site(cf)

    zone_name = site.site.route53
    access_key = site.site.aws_access_key
    secret_key = site.site.aws_secret_access_key
    domain = site.site.domain

    logger.info(f"Testing DNS record: {name}.{domain}")
    logger.debug(f"Using AWS Zone: {zone_name}")

    try:
        dns_store = DNSDataClass.openZone(zone_name, domain, access_key, secret_key)
    except Exception as e:
        logger.error(f"Failed to connect to Route53: {e}")
        sys.exit(1)

    record_name = f"{name}.{domain}"
    record_name_fqdn = f"{record_name}."
    chunked_data = [f'"{content}"']

    existing_record = None
    for rrset in dns_store.records:
        if rrset.name == record_name_fqdn:
            existing_record = rrset
            break

    try:
        if existing_record:
            logger.info(f"Record exists, updating: {record_name}")
            print(f"Updating existing TXT record: {record_name}")
            existing_record.records = chunked_data
            existing_record.ttl = ttl
            body = existing_record.save()
            logger.debug(f"Route53 response: {body}")
        else:
            logger.info(f"Creating new record: {record_name}")
            print(f"Creating new TXT record: {record_name}")
            rrset, body = dns_store._zone.create_txt_record(
                record_name, chunked_data, ttl=ttl
            )
            logger.debug(f"Route53 response: {body}")
    except Exception as e:
        logger.error(f"Failed to create/update DNS record '{record_name}': {e}")
        sys.exit(1)

    print(f"Content: {content}")
    print(f"TTL: {ttl}")
    print("")
    print("Waiting 30 seconds for DNS propagation...")
    time.sleep(30)

    print("")
    print("Verifying DNS record...")
    try:
        answer = dns.resolver.resolve(record_name, "TXT")
        retrieved = "".join([r.strings[0].decode("utf-8") for r in answer])
        print(f"Retrieved content: {retrieved}")
        if retrieved == content:
            print("Verification: PASSED")
        else:
            print(f"Verification: FAILED (expected '{content}')")
    except Exception as e:
        print(f"Verification: FAILED ({e})")

    print("")
    print("Cleaning up - deleting test record...")
    try:
        if existing_record:
            body = existing_record.delete()
        else:
            for rrset in dns_store._zone.record_sets:
                if rrset.name == record_name_fqdn and rrset.rrset_type == "TXT":
                    body = rrset.delete()
                    break
        print(f"Deleted TXT record: {record_name}")
        logger.debug(f"Route53 response: {body}")
    except Exception as e:
        logger.error(f"Failed to delete DNS record '{record_name}': {e}")
        sys.exit(1)

    return 0


if __name__ == "__main__":
    app()
