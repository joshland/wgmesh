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
roa4 table roa_v4;
roa6 table roa_v6;

protocol device DEVICE { }
protocol direct DIRECT { ipv4 { export all; }; ipv6 { export all; }; interface "*"; }
protocol kernel KERNEL4 { learn; ipv4 { import all; export all; }; merge paths; }
protocol kernel KERNEL6 { learn; ipv6 { import all; export all; }; merge paths; }

#protocol bfd {
#  interface "*" {
#    interval 50 ms;
#  };
#}

template bgp mesh_partner {
  local as {{ local_asn }};
  ipv4 {
    import filter {
      if ( net ~ [ 172.16.0.0/16+, 10.0.0.0/8+ ] ) then accept;
      reject;
    };
    export all;
    preference 160;
    extended next hop;
   };
   ipv6 {
     import filter {
       if ( net ~ [ 0::/0+ ] ) then accept;
       reject;
     };
     export all;
  };
  hold time 6;
  #bfd graceful;
  graceful restart;
}

{% for wg, values in wireguard_interfaces.items() %}
protocol bgp {{ wg }} from mesh_partner {
  interface "{{ wg }}";
  neighbor {{ values[0] }} as {{ values[1] }};
}
{% endfor %}

"""[1:]

ns_private = """
#!/bin/bash

## wgmesh - wgdeploy /usr/local/sbin/ns-private
#  GENERATED FILE - DO NOT EDIT BY HAND
###############################################################################
etcbird="/etc/bird"
etcwg="/etc/wireguard"

function start(){
  shift

  echo "stopping namespace: $1"

  ## default namespace
  /usr/bin/env ip addr add 169.254.{{ octet }}.1/24 brd + dev {{ interface_outbound }}
  /usr/bin/env ip link set netns $1 dev {{ interface_trust }}

  # up {{ interface_trust }}
  /usr/bin/env ip netns exec $1 ip link set {{ interface_trust }} up
  /usr/bin/env ip netns exec $1 ip addr add {{ interface_trust_ip }} brd + dev {{ interface_trust }}

  ## $1 namespace
  /usr/bin/env ip netns exec $1 ip addr add 169.254.{{ octet }}.2/24 brd + dev {{ interface_outbound }}
  /usr/bin/env ip netns exec $1 ip route add 0.0.0.0/1 via 169.254.{{ octet }}.1
  /usr/bin/env ip netns exec $1 ip route add 128.0.0.0/1 via 169.254.{{ octet }}.1
  /usr/bin/env systemctl restart shorewall --no-ask-password
}

function stop(){
    shift
    echo "stopping namespace: $1"

    /usr/bin/env ip netns exec $1 ip addr del {{ interface_trust_ip }} dev {{ interface_trust }}
    /usr/bin/env ip netns exec $1 ip link set {{ interface_trust }} down
    /usr/bin/env ip netns exec $1 ip link set netns 1 dev {{ interface_trust }}
}

if [ -z "$2" ]; then
    echo "Error! namespace name required!"
    exit 1
fi

case "$1" in
   start)
      start $*
   ;;
   stop)
      stop $*
   ;;
   restart)
      stop $*
      start $*
   ;;
   *)
      echo "Usage: $0 {start|stop|restart}"
esac

"""[1:]

ns_tester = """
#!/bin/bash

## wgmesh - wgdeploy /usr/local/sbin/ns-private
#  GENERATED FILE - DO NOT EDIT BY HAND
###############################################################################
etcbird="/etc/bird"
etcwg="/etc/wireguard"

function start(){
  shift

  echo "stopping namespace: $1"

  #/usr/bin/env ip netns delete tester
  #/usr/bin/env ip netns add tester
  #/usr/bin/env ip netns exec tester ip link set lo up
  #/usr/bin/env umount /var/run/netns/tester
  #/usr/bin/env mount --bind /proc/self/ns/net /var/run/netns/tester

  /usr/bin/env ip netns exec private ip link add tester1 type veth peer name tester1 netns tester
  /usr/bin/env ip netns exec private ip link set tester1 up
  /usr/bin/env ip netns exec tester ip link set lo up
  /usr/bin/env ip netns exec tester ip link set tester1 up
  /usr/bin/env ip netns exec tester sysctl -w net.ipv4.ip_forward=1
  /usr/bin/env ip netns exec tester sysctl -w net.ipv6.conf.all.forwarding=1

  ## default namespace
  /usr/bin/env ip addr add 169.254.{{ 100 + octet }}.1/24 brd + dev tester1

  ## $1 namespace
  /usr/bin/env ip netns exec private ip addr add 169.254.{{ 100 + octet }}.1/24 brd + dev tester1
  /usr/bin/env ip netns exec tester ip addr add 169.254.{{ 100 + octet }}.2/24 brd + dev tester1

  /usr/bin/env ip netns exec tester ip route add 10.0.0.0/8 via 169.254.{{ 100 + octet }}.1
  /usr/bin/env ip netns exec tester ip route add 172.126 via 169.254.{{ 100 + octet }}.1
  /usr/bin/env ip netns exec private ip route add 192.168.{{ 100 + octet }}.0/24 via 169.254.{{ 100 + octet }}.2

  /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.1/24 brd + dev lo
  /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.10/24 brd + dev lo
  /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.100/24 brd + dev lo
  /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.200/24 brd + dev lo

}

function stop(){
    shift
    echo "stopping namespace: $1"

}

if [ -z "$2" ]; then
    echo "Error! namespace name required!"
    exit 1
fi

case "$1" in
   start)
      start $*
   ;;
   stop)
      stop $*
   ;;
   restart)
      stop $*
      start $*
   ;;
   *)
      echo "Usage: $0 {start|stop|restart}"
esac

"""[1:]

mesh_start = """
#!/usr/bin/env bash

## wgmesh - wgdeploy /usr/local/sbin/mesh_wg_restart
#  DO NOT EDIT BY HAND
###############################################################################
{% for k, v in cmds.items() -%}
{{ k }}={{ v }}
{% endfor %}
loop=0

function start(){
    shift
    while [ $loop -eq 0 ]; do
	${binfping} 8.8.8.8 > /dev/null
	if [ $? ]; then
            loop=1
            echo "mesh startup: internet is alive."
	fi
	sleep 5
    done

    ## Start Wireguard
    {% for iface, addr in wireguard_interfaces.items() -%}
    echo "Starting: ${iface}"
    /usr/bin/env ip netns exec $1 /usr/bin/env wg-quick up {{ iface }}
    {% endfor %}
}

function stop(){
    shift
    {% for iface, addr in wireguard_interfaces.items() -%}
    echo "Stopping: ${iface}"
    /usr/bin/env ip netns exec $1 /usr/bin/env wg-quick down {{ iface }}
    {% endfor %}
}

if [ -z "$2" ]; then
    echo "Error! namespace name required!"
    exit 1
fi

case "$1" in
   start)
      start $*
   ;;
   stop)
      stop $*
   ;;
   restart)
      stop $*
      start $*
   ;;
   *)
      echo "Usage: $0 {start|stop|restart}"
esac

"""[1:]

## Tab align in rendered template.  (important for readability.)
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
Invalid(DROP)	net	all	tcp
Invalid(DROP)	net	all	udp
Invalid(DROP)	loc	net:172.16.0.0/12,10.0.0.0/8,192.168.0.0/16

# Accept DNS connections from the firewall to the Internet
DNS(ACCEPT)	$FW		net
NTP(ACCEPT)	$FW		net
SNMP(ACCEPT)	$FW		net
SSH(ACCEPT)	$FW		net

# Accept SSH connections from the local network to the firewall and DMZ
SSH(ACCEPT)	net		$FW
SSH(ACCEPT)	loc		$FW
## We don't need any 
#BGP(ACCEPT)	loc		$FW
#BGP(ACCEPT)	$FW		loc

{% for port in ports -%}
DNAT		net		loc:169.254.{{ octet }}.2	udp	{{ port }}
{% endfor %}
# Drop Ping from the "bad" net zone.
Ping(ACCEPT)   	net             $FW

# Make ping work bi-directionally between the dmz, net, Firewall and local zone
# (assumes that the loc-> net policy is ACCEPT).
Ping(ACCEPT)    loc             $FW
Ping(ACCEPT)    $FW             loc

SNMP(ACCEPT) 	loc		$FW

Ping(ACCEPT)	$FW		net		icmp
ACCEPT		$FW		loc		icmp
ACCEPT		$FW		loc

ACCEPT		$FW		net		tcp	https
ACCEPT		$FW		net		tcp	http

"""[1:]

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

"""[1:]

wireguard_conf = """
#
# Peering template generated template for {{ myhost }} => {{ Hostname }}
#
[Interface]
PrivateKey = {{ private_key }}
Address    = {{ tunnel_addresses }}
ListenPort = {{ local_port }}

# {{ Hostname }}
[Peer]
PublicKey  = {{ public_key }}
{%- if remote_address > '' %}
Endpoint   = {{ remote_address }}
{% endif %}
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepAlive = 25

"""[1:]
