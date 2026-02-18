#!/usr/bin/env python3
"""wgmesh site-specific operations"""

# Create the host basics locally
from logging import warning
import os
import sys
from io import StringIO
from glob import glob

import netaddr
import typer as t
from loguru import logger
from typing import Annotated, Any
from munch import munchify, Munch, unmunchify
from ruamel.yaml import YAML

from .endpointdata import Endpoint
from .datalib import message_encode, message_decode, dns_query
from .datalib import fetch_and_decode_record
from .lib import LoggerConfig, filediff
from .version import VERSION
from .crypto import *
from .hostlib import get_local_addresses_with_interfaces
from .templates import bird_private, ns_private, ns_tester, mesh_start, wireguard_conf
from .templates import render

app = t.Typer()


def hostfile(locus: str, config_path: str) -> Any:
    """common filename configuration"""
    retval = {
        "cfg_file": os.path.join(config_path, f"node_{locus}.yaml"),
        "sync_file": os.path.join(config_path, f"node_{locus}_siterecord.yaml"),
        "privkey": os.path.join(config_path, f"node_{locus}.key"),
        "pubkey": os.path.join(config_path, f"node_{locus}.pub"),
    }

    return munchify(retval)


def configure(
    filenames: dict,
    ep: Endpoint,
    hostname: str,
    trust_iface: str,
    trust_addrs: str,
    public_iface: str,
    public_addrs: str,
    asn: int,
    dryrun: bool,
) -> Endpoint:
    """handle configuration"""
    old_data = ep.save_endpoint_config()

    if hostname:
        ep.hostname = hostname
    if trust_iface:
        ep.trust_iface = trust_iface
    if public_iface:
        ep.public_iface = public_iface
    if trust_addrs:
        ep.trust_address = trust_addrs.split(",")
    if public_addrs:
        ep.public_address = public_addrs.split(",")
    if public_addrs:
        ep.asn = asn

    new_data = ep.save_endpoint_config()
    diffdata = filediff(
        old_data, new_data, f"{filenames.cfg_file}.old", filenames.cfg_file
    )
    if dryrun:
        print(diffdata)
    else:
        logger.info(f"Save file {filenames.cfg_file}")
        print(diffdata)
        with open(filenames.cfg_file, "w", encoding="utf-8") as cf:
            cf.write(new_data)
    return ep


@app.command()
def init(
    locus: Annotated[str, t.Argument(help="Site locus")],
    domain: Annotated[str, t.Argument(help="Locus domain name")],
    config_path: Annotated[str, t.Argument(envvar="WGM_CONFIG")] = "/etc/wireguard",
    hostname: Annotated[str, t.Option(help="Explicitly Set Hostname")] = None,
    trust_iface: Annotated[str, t.Option(help="Trusted Interface")] = "",
    trust_addrs: Annotated[
        str, t.Option(help="Trusted Addresses (delimit w/ comma")
    ] = "",
    public_iface: Annotated[str, t.Option(help="Public Interface")] = "",
    public_addrs: Annotated[
        str, t.Option(help="Public Addresses (delimt w/ comma")
    ] = False,
    asn: Annotated[int, t.Option(help="ASN number")] = -1,
    test_mode: Annotated[
        str, t.Option(help="Test mode: read DNS records from local folder")
    ] = "",
    force: Annotated[bool, t.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, t.Option(help="do not write anything")] = False,
    debug: Annotated[bool, t.Option(help="debug logging")] = False,
    trace: Annotated[bool, t.Option(help="trace logging")] = False,
):
    """
    initial wgmesh site configuration, key generation and site buildout

    requires: locus and wgmesh
    """
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)

    for x in (filenames.cfg_file, filenames.pubkey, filenames.privkey):
        if os.path.exists(x) and not (force or dryrun):
            logger.error(f"{x} exists, aborting (use --force to overwrite)")
            sys.exit(4)

    locus_info = fetch_and_decode_record(domain, test_mode)
    if not locus_info:
        logger.error(f"Failed to fetch record, aborting")
        sys.exit(1)

    newkey = generate_key()
    if dryrun:
        print(f"Generated key, ignoring (dryrun)")
    else:
        with open(filenames.privkey, "w", encoding="utf-8") as keyf:
            keyf.write(keyexport(newkey))
            pass
        with open(filenames.pubkey, "w", encoding="utf-8") as keyf:
            keyf.write(keyexport(newkey.public_key))
            pass
        pass

    ep = Endpoint(
        locus,
        domain,
        locus_info["publickey"],
        secret_key_file=filenames.privkey,
        public_key_file=filenames.pubkey,
    )

    configure(
        filenames,
        ep,
        hostname,
        trust_iface,
        trust_addrs,
        public_iface,
        public_addrs,
        asn,
        dryrun,
    )
    return 0


@app.command(name="set")
def set_config(
    locus: Annotated[str, t.Argument(help="Site locus")],
    config_path: Annotated[str, t.Argument(envvar="WGM_CONFIG")] = "/etc/wireguard",
    domain: Annotated[str, t.Option(help="Locus domain name")] = None,
    hostname: Annotated[str, t.Option(help="Explicitly Set Hostname")] = None,
    trust_iface: Annotated[str, t.Option(help="Trusted Interface")] = "",
    trust_addrs: Annotated[
        str, t.Option(help="Trusted Addresses (delimit w/ comma")
    ] = "",
    public_iface: Annotated[str, t.Option(help="Public Interface")] = "",
    public_addrs: Annotated[
        str, t.Option(help="Public Addresses (delimt w/ comma")
    ] = "",
    asn: Annotated[int, t.Option(help="ASN number")] = -1,
    test_mode: Annotated[
        str, t.Option(help="Test mode: read DNS records from local folder")
    ] = "",
    no_validate: Annotated[
        bool, t.Option(help="Skip DNS validation (for initial setup)")
    ] = False,
    force: Annotated[bool, t.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, t.Option(help="do not write anything")] = False,
    debug: Annotated[bool, t.Option(help="debug logging")] = False,
    trace: Annotated[bool, t.Option(help="trace logging")] = False,
):
    """site (re)configuration"""
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)

    with open(filenames.cfg_file, "r", encoding="utf-8") as cf:
        ep = Endpoint.load_endpoint_config(
            cf, validate=not no_validate, test_mode=test_mode
        )

    if domain:
        if domain != ep.site_domain:
            logger.error(f"{domain} != {ep.site_domain}")
            logger.error("Changing the domain name is not supported at this time.")
            sys.exit(1)
        pass

    if not no_validate:
        locus_info = fetch_and_decode_record(ep.site_domain, test_mode)
        if not locus_info:
            logger.error(f"Failed to fetch record, aborting")
            sys.exit(1)

    configure(
        filenames,
        ep,
        hostname,
        trust_iface,
        trust_addrs,
        public_iface,
        public_addrs,
        asn,
        dryrun,
    )

    return 0


@app.command()
def publish(
    locus: Annotated[
        str, t.Argument(help="short/familiar name, short hand for this mesh")
    ],
    config_path: Annotated[str, t.Argument(envvar="WGM_CONFIG")] = "/etc/wireguard",
    outfile: Annotated[str, t.Option(help="Output file")] = "",
    force: Annotated[bool, t.Option(help="force overwrite")] = False,
    dryrun: Annotated[bool, t.Option(help="do not write anything")] = False,
    debug: Annotated[bool, t.Option(help="debug logging")] = False,
    trace: Annotated[bool, t.Option(help="trace logging")] = False,
):
    """publish site registration - must be imported by wgsite master"""
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)
    with open(filenames.cfg_file, "r", encoding="utf-8") as cf:
        ep = Endpoint.load_endpoint_config(cf)
        pass
    ep.open_keys()

    clear_payload = ep.publish().toJSON()
    logger.trace(f"Site Registration Package: {clear_payload}")
    b64_cipher_payload = ep.encrypt_message(clear_payload)

    logger.debug(f"Encrypted Package: {len(clear_payload)}/{len(b64_cipher_payload)}")
    logger.trace(f"Payload: {b64_cipher_payload}")

    host_package = munchify(
        {"publickey": ep.public_key_encoded, "message": b64_cipher_payload}
    ).toJSON()
    host_message = message_encode(host_package)

    if outfile:
        if os.path.exists(outfile) and not force:
            print(f"Error: {outfile} exists, use --force to override")
            sys.exit(4)
        with open(outfile, "w", encoding="utf-8") as mf:
            mf.write(host_message)
    else:
        print('Transmit the following b64 string, and use "wgsite host"')
        print(host_message)
        pass

    # uuid: 2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d
    # public_key: o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=
    # public_key_file: /etc/wireguard/x707_pub
    # private_key_file: /etc/wireguard/x707_priv
    # local_ipv4: oob.x707.ashbyte.com
    # local_ipv6: ''
    return 0


@app.command(name="check")
def check_host(
    ignore: Annotated[
        str, t.Option(help="Comma-delimited list of interfaces to ignore")
    ] = "",
    config_path: Annotated[str, t.Argument(envvar="WGM_CONFIG")] = "/etc/wireguard",
    test_mode: Annotated[
        str, t.Option(help="Test mode: read DNS records from local folder")
    ] = "",
    debug: Annotated[bool, t.Option(help="debug logging")] = False,
    trace: Annotated[bool, t.Option(help="trace logging")] = False,
):
    """generate a local site report"""
    LoggerConfig(debug, trace)

    import shutil

    skip_list = ignore.split(",")

    cmdfping = shutil.which("fping")
    if4, if6 = get_local_addresses_with_interfaces(skip_list)

    # report
    print("Located")
    print(f"  fping: {cmdfping}")
    print(f"  ipv4 addresses, by interface:{if4}")
    print(f"  ipv6 addresses, by interface:{if6}")

    for x in glob(f"{config_path}/*.yaml"):
        try:
            with open(x, "r", encoding="utf-8") as cf:
                ep = Endpoint.load_endpoint_config(cf, test_mode=test_mode)
        except:
            print(f"Not an endpoint / invalid endpoint: {x}")
            raise
            continue
        print(f"Found Endpoint: {x} / {ep.locus}")
        continue
    # uuid: 2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d
    # public_key: o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=
    # public_key_file: /etc/wireguard/x707_pub
    # private_key_file: /etc/wireguard/x707_priv
    # local_ipv4: oob.x707.ashbyte.com
    # local_ipv6: ''
    return 0


@app.command()
def sync(
    locus: Annotated[
        str, t.Argument(help="short/familiar name, short hand for this mesh")
    ],
    config_path: Annotated[str, t.Argument(envvar="WGM_CONFIG")] = "/etc/wireguard",
    test_mode: Annotated[
        str, t.Option(help="Test mode: read DNS records from local folder")
    ] = "",
    dryrun: Annotated[bool, t.Option(help="do not write anything")] = False,
    debug: Annotated[bool, t.Option(help="debug logging")] = False,
    trace: Annotated[bool, t.Option(help="trace logging")] = False,
):
    """sync core changes from deployment-notices to local machine"""
    LoggerConfig(debug, trace)

    filenames = hostfile(locus, config_path)
    with open(filenames.cfg_file, "r", encoding="utf-8") as cf:
        ep = Endpoint.load_endpoint_config(cf)
        pass
    old_config = ep.save_endpoint_config()
    ep.open_keys()

    target = f"{str(ep.uuid)}.{ep.site_domain}"
    try:
        if test_mode:
            from .datalib import test_dns_query_host

            crypt = test_dns_query_host(str(ep.uuid), ep.site_domain, test_mode)
        else:
            crypt = dns_query(target)
    except:
        logger.error(f"DNS Exception: {target}")
        print()
        sys.exit(1)
    sync_payload = munchify({}).fromJSON(ep.decrypt_message(crypt))
    yaml = YAML(typ="rt")
    if sync_payload.asn != ep.asn:
        logger.info(f"Update ASN from Site: {ep.asn} => {sync_payload.asn}")
        new_config = ep.save_endpoint_config()
    if dryrun:
        print("nothing saved")
        sys.exit(1)
    with open(filenames.sync_file, "w") as sync_file:
        yaml.dump(unmunchify(sync_payload), sync_file)
    diffdata = filediff(
        old_config, new_config, f"{filenames.cfg_file}.old", filenames.cfg_file
    )
    print("Changeset:")
    print(diffdata)
    if sync_payload.asn != ep.asn:
        logger.info(f"Update ASN from Site: {ep.asn} => {sync_payload.asn}")
        with open(filenames.cfg_file, "w", encoding="utf-8") as cf:
            cf.write(new_config)
    return 0


def deployfile(locus: str, deploy_path: str) -> Munch:
    """common filename configuration"""
    retval = {
        "ns_private": os.path.join(deploy_path, "usr/local/sbin/ns-private"),
        "ns_tester": os.path.join(deploy_path, "usr/local/sbin/ns-tester"),
        "mesh_wg_restart": os.path.join(deploy_path, "usr/local/sbin/mesh_wg_restart"),
        "meth_ns_init": os.path.join(deploy_path, "usr/local/sbin/mesh_wg_init"),
        "bird_private": os.path.join(deploy_path, "etc/bird/bird_private"),
        "bird_conf_d": os.path.join(deploy_path, "etc/bird/bird_private_local.d"),
    }
    return munchify(retval)


@app.command()
def deploy(
    locus: Annotated[
        str, t.Argument(help="short/familiar name, short hand for this mesh")
    ],
    config_path: Annotated[str, t.Argument(envvar="WGM_CONFIG")] = "/etc/wireguard",
    deploy_path: Annotated[str, t.Option(help="base for install")] = "/",
    dryrun: Annotated[bool, t.Option(help="do not write anything")] = False,
    debug: Annotated[bool, t.Option(help="debug logging")] = False,
    trace: Annotated[bool, t.Option(help="trace logging")] = False,
):
    """deploy local wgmesh configuration and scripts"""
    LoggerConfig(debug, trace)
    yaml = YAML(typ="rt")

    filenames = hostfile(locus, config_path)
    with open(filenames.cfg_file, "r", encoding="utf-8") as cf:
        ep = Endpoint.load_endpoint_config(cf)
        pass
    ep.open_keys()

    with open(filenames.sync_file, "r") as sync_file:
        sync_file = munchify(yaml.load(sync_file))

    portbase = sync_file.portbase
    site = sync_file.site
    tunnel_network = netaddr.IPNetwork(sync_file.remote)
    tunnel_net_base = str(tunnel_network.network).split("::")[0]
    mykey = open(ep.secret_key_file, "r").read().strip()
    template_args = munchify({})
    template_args.interface_outbound = ep.public_iface
    template_args.interface_trust = ep.trust_iface
    template_args.wireguard_interfaces = {}
    template_args.cmds = {"binfping": ep.cmdfping}
    template_args.locus = ep.locus
    template_args.myhost = ep.hostname
    template_args.local_asn = ep.asn
    template_args.octet = sync_file.octet
    template_args.tunnel_remote = sync_file.remote
    deploy_files = deployfile(locus, deploy_path)
    for host, values in sync_file.hosts.items():
        index = values.localport - sync_file.portbase
        remotes = ""
        if len(values.remote):
            remotes = ",".join(
                [f"{str(x)}:{values.remoteport}" for x in values.remote.split(",")]
            )
            portpoints = [sync_file.octet]
            portpoints.append(index)
            netbits = "".join(
                ["{:02X}".format(a) for a in sorted(portpoints, reverse=True)]
            )
            local_endpoint_addr = (
                f"{tunnel_net_base}:{netbits}::{deploy_message['octet']}/64"
            )
            remote_endpoint_addr = f"{tunnel_net_base}:{netbits}::{index}"
            listen_address = template_args["interface_trust_ip"].split("/")[0]

            fulfill = {
                "myhost": ep.hostname,
                "Hostname": host,
                "interface_outbound": template_args.interface_outbound,
                "interface_public": template_args.interface_public,
                "interface_trust": template_args.interface_trust,
                "listen_address": listen_address,
                "local_port": values["localport"],
                "octet": deploy_message["octet"],
                "private_key": mykey,
                "public_key": values["key"],
                "remote_address": remotes,
                "tunnel_addresses": local_endpoint_addr,
            }
            template_args.ports.append(values["localport"])
            template_args.wireguard_interfaces[f"wg{index}"] = [
                remote_endpoint_addr,
                values["asn"],
            ]
            template_args.local_endpoint_addr = local_endpoint_addr
            wgconf = render(wireguard_conf, fulfill)
            if dry_run:
                logger.info(f"Dry-run Mode.")
                print(wgconf)
            else:
                check_update_file(
                    wgconf, os.path.join(deploy_path, f"/etc/wireguard/wg{index}.conf")
                )
                pass
            continue

        nssysvinit = render(ns_private, template_args)
        tssysvinit = render(ns_tester, template_args)
        meshstart = render(mesh_start, template_args)
        bird_priv = render(bird_private, template_args)
        check_update_file(nssysvinit, deploy_file.ns_private)
        check_update_file(tssysvinit, deploy_file.ns_tester)
        check_update_file(meshstart, deploy_file.mesh_wg_restart)
        check_update_file(bird_priv, deploy_file.bird_private)
        for x in (
            deploy_file.ns_private,
            deploy_file.ns_tester,
            deploy_file.mesh_wg_restart,
        ):
            os.chmod(x, 0o750)
            continue
        os.chmod(deploy_file.bird_private, 0o640)
        buser = pwd.getpwnam("bird").pw_uid
        bgroup = pwd.getpwnam("bird").pw_gid
        if not os.path.exists(deploy_file.bird_conf_d):
            os.makedirs(deploy_file.bird_conf_d)
            try:
                os.chown(deploy_file.bird_conf_d, buser, bgroup)
            except PermissionError:
                logger.warning(f"Failed to set ownership of {deploy_file.bird_conf_d}")
                pass
            pass
        try:
            os.chown(deploy_file.bird_private, buser, bgroup)
        except PermissionError:
            logger.warning(f"Failed to set ownership of /etc/bird/bird_private.conf")
        return 0


if __name__ == "__main__":
    app()
