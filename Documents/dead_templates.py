
namespace_start = """
#!/bin/bash

## wgmesh - wgdeploy /usr/local/sbin/mesh_ns_init
#  DO NOT EDIT BY HAND
###############################################################################
{% for k, v in cmds.items() -%}
{{ k }}={{ v }}
{% endfor %}
etcbird="/etc/bird"
etcwg="/etc/wireguard"

## NS Creation
${binip} netns add private

## Add {{ interface_trust }}
${binip} link set netns private dev {{ interface_trust }}
${binip} netns exec private ${binip} addr add 127.0.0.1/8 dev lo
${binip} netns exec private ${binip} addr add {{ interface_trust_ip }} dev {{ interface_trust }}
${binip} link add {{ interface_outbound }} type veth peer name {{ interface_outbound }} netns private

## Start all affected Interfaces
${binip} netns exec private ${binip} link set lo up
${binip} netns exec private ${binip} link set {{ interface_trust }} up
${binip} netns exec private ${binip} link set {{ interface_outbound }} up
${binip} link set {{ interface_outbound }} up

## Establish Namespace Uplink
${binip} netns exec private ${binip} addr add 169.254.{{ octet }}.2/24 dev {{ interface_outbound }}
${binip} addr add 169.254.{{ octet }}.1/24 dev {{ interface_outbound }}
${binip} netns exec private ${binip} route add 0.0.0.0/1 via 169.254.{{ octet }}.1
${binip} netns exec private ${binip} route add 128.0.0.0/1 via 169.254.{{ octet }}.1

## Activate Firewall
${binsys} start shorewall

## Enable Routing
${binip} netns exec private sysctl -qw net.ipv6.conf.all.forwarding=1
${binip} netns exec private sysctl -qw net.ipv4.conf.all.forwarding=1

## Start Private Routing Daemon
## ${binip} netns exec

"""

