## templates
from jinja2 import Template, Environment, FileSystemLoader, StrictUndefined

env = Environment(loader=FileSystemLoader("."))
env.undefined = StrictUndefined

def render(template, args):
    ''' return a string with a rendered template '''
    t = env.from_string(template)
    return t.render(args)

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

## Establish Namespace Uplink
ip netns exec private ip addr add 169.254.{{ octet }}.2/24 dev {{ interface_outbound }}
ip addr add 169.254.{{ octet }}.1/24 dev {{ interface_outbound }}
ip netns exec private ip route add 0.0.0.0/1 via 169.254.{{ octet }}.1
ip netns exec private ip route add 128.0.0.0/1 via 169.254.{{ octet }}.1

ip netns exec private ip link set lo up
ip netns exec private ip link set {{ interface_trust }} up
ip netns exec private ip link set {{ interface_outbound }} up
ip link set {{ interface_outbound }} up
shorewall restart

## Enable Routing
ip netns exec private sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec private sysctl -qw net.ipv4.conf.all.forwarding=1

## Start Private Routing Daemon
## ip netns exec 

## Start Wireguard
{% for iface in wireguard_interfaces -%}
ip netns exec private wg-quick up {{ iface }}
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
Ping(DROP)   	net             $FW

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
