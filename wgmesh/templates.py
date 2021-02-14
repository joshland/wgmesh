## templates
from jinja2 import Template, Environment, FileSystemLoader, StrictUndefined

env = Environment(loader=FileSystemLoader("."))
env.undefined = StrictUndefined

def render(template, args):
    ''' return a string with a rendered template '''
    t = env.from_string(template)
    return t.render(args)

bird_private = """
log syslog { debug, trace, info, remote, warning, error, auth, fatal, bug };
router id 1.0.{{ octet }}.1;

protocol device {
   scan time 10;
}

protocol bfd {
    interface "*" {
        interval 50 ms;
    };
}

protocol kernel {
   persist;
   learn;
   ipv4 {
       import all;
       export all;
   };
   merge paths yes;
}

protocol kernel {
   persist;
   learn;
   ipv6 {
       import all;
       export all;
   };
   merge paths yes;
}

template bgp mesh_partner {
   local as {{ local_asn }};
   ipv4 {
       import all;
       export all;
       #export where ifname ~ "eth*";
       #preference 160;
       #extended next hop;
   };
   ipv6 {
       import all;
       export all;
       #export where ifname ~ "eth*";
   };
   hold time 6;
   bfd;
   graceful restart;
}

{% for wg, values in wireguard_interfaces.items() %}
protocol bgp partner_{{ wg }} from mesh_partner {
   interface "{{ wg }}";
   neighbor {{ values[0] }} as {{ values[1] }};
}
{% endfor %}

"""

namespace_start = """
## wgmesh - wgdeploy /usr/local/sbin/namespace_init
#  DO NOT EDIT BY HAND
###############################################################################

## NS Creation
ip netns add private

## Add {{ interface_trust }}
ip link set netns private dev {{ interface_trust }}
ip netns exec private ip addr add 127.0.0.1/8 dev lo
ip netns exec private ip addr add {{ interface_trust_ip }} dev {{ interface_trust }}
ip link add {{ interface_outbound }} type veth peer name {{ interface_outbound }} netns private

## Start all affected Interfaces
ip netns exec private ip link set lo up
ip netns exec private ip link set {{ interface_trust }} up
ip netns exec private ip link set {{ interface_outbound }} up
ip link set {{ interface_outbound }} up

## Establish Namespace Uplink
ip netns exec private ip addr add 169.254.{{ octet }}.2/24 dev {{ interface_outbound }}
ip addr add 169.254.{{ octet }}.1/24 dev {{ interface_outbound }}
ip netns exec private ip route add 0.0.0.0/1 via 169.254.{{ octet }}.1
ip netns exec private ip route add 128.0.0.0/1 via 169.254.{{ octet }}.1

## Activate Firewall
systemctl start shorewall

## Enable Routing
ip netns exec private sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec private sysctl -qw net.ipv4.conf.all.forwarding=1

## Start Private Routing Daemon
## ip netns exec 

## Start Wireguard
{% for iface, addr in wireguard_interfaces.items() -%}
ip netns exec private wg-quick down {{ iface }}
ip netns exec private wg-quick up {{ iface }}
{% endfor %}

"""

vrf_start = """
## wgmesh - wgdeploy /usr/local/sbin/vrf_init
#  DO NOT EDIT BY HAND
###############################################################################

## NS Creation
ip vrf add private

## Add {{ interface_trust }}
ip link set vrf private dev {{ interface_trust }}
ip vrf exec private ip addr add 127.0.0.1/8 dev lo
ip vrf exec private ip addr add {{ interface_trust_ip }} dev {{ interface_trust }}
ip link add {{ interface_outbound }} type veth peer name {{ interface_outbound }} vrf private

## Activate network links
ip vrf exec private ip link set lo up
ip vrf exec private ip link set {{ interface_trust }} up
ip vrf exec private ip link set {{ interface_outbound }} up
ip link set {{ interface_outbound }} up

## Establish Namespace Uplink
ip vrf exec private ip addr add 169.254.{{ octet }}.2/24 dev {{ interface_outbound }}
ip addr add 169.254.{{ octet }}.1/24 dev {{ interface_outbound }}
ip vrf exec private ip route add 0.0.0.0/1 via 169.254.{{ octet }}.1
ip vrf exec private ip route add 128.0.0.0/1 via 169.254.{{ octet }}.1

## Activate Firewall
shorewall restart

## Enable Routing
ip vrf exec private sysctl -qw net.ipv6.conf.all.forwarding=1
ip vrf exec private sysctl -qw net.ipv4.conf.all.forwarding=1

## Start Private Routing Daemon
## ip vrf exec 

## Start Wireguard
{% for iface, addr in wireguard_interfaces.items() -%}
ip vrf exec private wg-quick down {{ iface }}
ip vrf exec private wg-quick up {{ iface }}
{% endfor %}

"""

shorewall_rules = """
## wgmesh - wgdeploy /etc/shorewall/rules
#  DO NOT EDIT BY HAND
######################################################################################################################################################################################################
#ACTION		SOURCE		DEST		PROTO	DEST	SOURCE		ORIGINAL	RATE		USER/	MARK	CONNLIMIT	TIME		HEADERS		SWITCH		HELPER
#							PORT	PORT(S)		DEST		LIMIT		GROUP
?SECTION ALL
?SECTION ESTABLISHED
?SECTION RELATED
?SECTION INVALID
?SECTION UNTRACKED
?SECTION NEW

# Don't allow connection pickup from the net
Invalid(DROP)	net		all		tcp

# Accept DNS connections from the firewall to the Internet
DNS(ACCEPT)	    $FW		net
NTP(ACCEPT)	    $FW		net
SSH(ACCEPT)	    $FW		net

# Accept SSH connections from the local network to the firewall and DMZ
SSH(ACCEPT)     net             $FW
SSH(ACCEPT)     loc             $FW
## We don't need any 
#BGP(ACCEPT)     loc             $FW
#BGP(ACCEPT)     $FW		        loc

{% for port in ports -%}
DNAT            net             loc:169.254.{{ octet }}.2  udp     {{ port }}
{% endfor %}
# Drop Ping from the "bad" net zone.
Ping(ACCEPT)   	net             $FW

# Make ping work bi-directionally between the dmz, net, Firewall and local zone
# (assumes that the loc-> net policy is ACCEPT).
Ping(ACCEPT)    loc             $FW
Ping(ACCEPT)    $FW             loc

SNMP(ACCEPT) 	loc		$FW

Ping(ACCEPT)	$FW		net		icmp
ACCEPT		    $FW		loc		icmp
ACCEPT		    $FW		loc

ACCEPT		    $FW		net		tcp		https
ACCEPT		    $FW		net		tcp		http

"""

shorewall_interfaces = """
## wgmesh - wgdeploy /etc/shorewall/interfaces
#  DO NOT EDIT BY HAND
###############################################################################
?FORMAT 2
###############################################################################
#ZONE	INTERFACE	OPTIONS
net     NET_IF      tcpflags,nosmurfs,routefilter,sourceroute=0,physical={{ interface_public }}
loc     LOC_IF      tcpflags,routefilter,physical={{ interface_outbound }}
#dmz    DMZ_IF      tcpflags,nosmurfs,routefilter,logmartians,physical={{ wireguard_interface | default('wg+') }}

"""

wireguard_conf = """
#
# Peering template generated template for {( myhost )} => {{ Hostname }}
#
[Interface]
PrivateKey = {{ private_key }}
Address    = {{ tunnel_addresses }}
ListenPort = {{ local_port }}

# {{ Hostname }}
[Peer]
PublicKey  = {{ public_key }}
{% if remote_address > '' -%}
Endpoint   = {{ remote_address }}
{% endif %}
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepAlive = 25
"""
