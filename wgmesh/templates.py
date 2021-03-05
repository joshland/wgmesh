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

protocol direct DIRECT {
   ipv4 { export all; };
   ipv6 { export all; };
   interface "-private*";
   interface "*";
}

protocol kernel KERNEL4 {
   learn; merge paths yes limit; persist; ipv4 { import all; export all; };
}

protocol kernel KERNEL6 {
   learn; merge paths yes limit; persist; ipv6 { import all; export all; };
}

{% for wgname, table in routing_tables.items() %}
ipv4 table {{ table.name }}_4;
ipv6 table {{ table.name }}_6;

protocol kernel {{ wgname }}_4 {
   learn; merge paths; persist;
   kernel table {{ table.id }};
   ipv4 {
      table {{ table.name }}_4;
      export all;
   };
}

protocol kernel {{ wgname }}_6 {
   learn; merge paths; persist;
   kernel table {{ table.id }};
   ipv6 {
      table {{ table.name }}_6;
      export all;
   };
}

{% endfor %}

protocol bfd {
  interface "*" {
    interval 50 ms;
  };
}

template bgp mesh_partner {
  local as {{ local_asn }};
  ipv4 {
    import filter {
      if ( net ~ [ 172.16.0.0/16+, 10.0.0.0/8+, 192.168.0.0/16+ ] ) then accept;
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
  bfd graceful;
  graceful restart;
  enable extended messages;
}

{% for wg, values in wireguard_interfaces.items() %}
protocol bgp {{ wg }} from mesh_partner {
  interface "{{ wg }}";
  neighbor {{ values[0] }} as {{ values[1] }} external;
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

function cmd(){
   echo "RUNCMD: $*"
   $* || echo "FAILED"
   return $?
}

function start(){
  shift

  echo "stopping namespace: $1"

  ## default namespace
  cmd /usr/bin/env ip addr add 169.254.{{ octet }}.1/24 brd + dev {{ interface_outbound }}
  cmd /usr/bin/env ip link set netns $1 dev {{ interface_trust }}

  # up {{ interface_trust }}
  cmd /usr/bin/env ip netns exec $1 ip link set {{ interface_trust }} up
  cmd /usr/bin/env ip netns exec $1 ip addr add {{ interface_trust_ip }} brd + dev {{ interface_trust }}

  ## $1 namespace
  cmd /usr/bin/env ip netns exec $1 ip addr add 169.254.{{ octet }}.2/24 brd + dev {{ interface_outbound }}
  cmd /usr/bin/env ip netns exec $1 ip route add 0.0.0.0/1 via 169.254.{{ octet }}.1
  cmd /usr/bin/env ip netns exec $1 ip route add 128.0.0.0/1 via 169.254.{{ octet }}.1
  cmd /usr/bin/env systemctl restart shorewall --no-ask-password

  ## Start Routing
  cmd /usr/bin/env ip netns exec $1 sysctl -w net.ipv4.ip_forward=1
  cmd /usr/bin/env ip netns exec $1 sysctl -w net.ipv6.conf.all.forwarding=1

  if [[ -e "/usr/local/sbin/ns-${1}-local" ]]; then
      cmd /usr/bin/env ip netns exec tester /usr/local/sbin/ns-${1}-local start $1;
  fi
}

function stop(){
    shift
    echo "stopping namespace: $1"

    cmd /usr/bin/env ip netns exec $1 ip addr del {{ interface_trust_ip }} dev {{ interface_trust }}
    cmd /usr/bin/env ip netns exec $1 ip link set {{ interface_trust }} down
    cmd /usr/bin/env ip netns exec $1 ip link set netns 1 dev {{ interface_trust }}
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

## wgmesh - wgdeploy /usr/local/sbin/ns-tester
#  GENERATED FILE - DO NOT EDIT BY HAND
###############################################################################
etcbird="/etc/bird"
etcwg="/etc/wireguard"

function cmd(){
   echo "RUNCMD: $*"
   $* || echo "FAILED"
   return $?
}

function start(){
  shift

  echo "stopping namespace: $1"

  ## Private Setup
  cmd /usr/bin/env ip netns exec private ip link add tester1 type veth peer name tester1 netns tester
  cmd /usr/bin/env ip netns exec private ip link set tester1 up

  ## Tester Setup
  cmd /usr/bin/env ip netns exec tester ip link set lo up
  cmd /usr/bin/env ip netns exec tester ip link set tester1 up
  cmd /usr/bin/env ip netns exec tester sysctl -w net.ipv4.ip_forward=1
  cmd /usr/bin/env ip netns exec tester sysctl -w net.ipv6.conf.all.forwarding=1

  ## IPv4 Address
  #cmd /usr/bin/env ip netns exec private ip addr add 169.254.{{ 100 + octet }}.1/24 brd + dev tester1
  #cmd /usr/bin/env ip netns exec tester ip addr add 169.254.{{ 100 + octet }}.2/24 brd + dev tester1

  ## Test Addresses (lo)
  cmd /usr/bin/env ip netns exec private ip addr add 192.168.{{ 100 + octet }}.1/24 brd + dev tester1
  cmd /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.10/24 brd + dev tester1
  cmd /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.100/24 brd + dev tester1
  cmd /usr/bin/env ip netns exec tester ip addr add 192.168.{{ 100 + octet }}.200/24 brd + dev tester1
  cmd /usr/bin/env ip netns exec tester ip route add default via 192.168.{{ 100 + octet }}.1

  ## Test Routes
  #cmd /usr/bin/env ip netns exec private ip route add 192.168.{{ 100 + octet }}.0/24 via 169.254.{{ 100 + octet }}.2
  #cmd /usr/bin/env ip netns exec tester ip route add default via 169.254.{{ 100 + octet }}.1

  if [[ -e "/usr/local/sbin/ns-tester-local" ]]; then
      cmd /usr/bin/env ip netns exec tester /usr/local/sbin/ns-tester-local start tester;
  fi
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

DNAT:info	net		loc:169.254.{{ octet }}.2	udp	{{ ports | join(',') }}
#ACCEPT		net		loc		udp	{{ ports | join(',') }}
#ACCEPT		net		$FW		udp	{{ ports | join(',') }}

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

"""[1:]

wireguard_conf = """
#
# Peering template generated template for {{ myhost }} => {{ Hostname }}
#
[Interface]
PrivateKey = {{ private_key }}
Address    = {{ tunnel_addresses }}
ListenAddress = {{ listen_address }}
ListenPort = {{ local_port }}
Table      = {{ route_table_id }}  #{{ route_table_name }}

# {{ Hostname }}
[Peer]
PublicKey  = {{ public_key }}
{% if remote_address > '' %}
Endpoint   = {{ remote_address }}
{% endif -%}
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepAlive = 25

"""[1:]
