# Wgmesh Overview

Configures basic details for sites.  The essential goal is to use `wgmesh` to locally configure wireguard and BIRD for tunnel deployment and route exchange.

Bootstrapping
  TXT Records:
    _wg.[domain]
    locus
    public key

Creates local /etc/wireguard/[locus]_priv,  /etc/wireguard/[locus]_pub

Encodes the public key and transmits everything.


Local Creation:

  Local Wireguard configuration
    - local key creation

### Port Allocations

The port allocations beginning at `portbase` + [octet] of the site.  The script will automatically assign addresses for ipv4 and ipv6 addresses.

### Basic Configuration Keywords

    #!YAML
    global:
        alerts: [email address]
        domain: [domain, unsued]
        ipv4: [ RFC1918 private tunnel network]
        ipv6: [ IPV6 Reserve Range network ]
        locus: [short name]
        portbase: [ starting port ]
        publickey: [ed2559 pubkey]
    hosts:
        hostname:
            ipv4: [ipv4 address from the global ipv4 ]
            ipv6: [ipv6 address from the global ipv6 ]
            local_networks: [ list of local static routes ]
            private_key_file: [ path to private key file ]]
            public_key: [ public key ]

###  Minimalist Example:

    #!YAML
    global:
      alerts: alerts@othersite.is
      domain: othersite.is
      ipv4: 172.16.44.0/24
      ipv6: fd86:ea04:1116::/64
      locus: poke_frr
      portbase: 49900
    hosts:
      vpn-abbot.othersite.is: {}
      vpn-abash.othersite.is: {}

