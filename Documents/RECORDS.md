## This project over all

The project is a simple document translation program for building, changing,
and securely publishing documents to remote sites. The first communication medium
is dns-based publishing.

## Document Transports

### DNS - ubiquitous, and "free" access

- Access key requirements
- Does not provide feedback to site manager.

### S3 Bucket

- Access keys requirements
- Allows for versioning
- Low cost
- Pulumi-based configuration
- Storage proxy

### API

- Rapid response
- Simple management
- Pulumi-based deployment
- Operates as a store-and-forward proxy.

## Site Management Document

Site configuration file:

        global:
          alerts: ''
          asn_range: 4200000000:4200000010
          aws_access_key: toastmeat
          aws_secret_access_key: farkwalkd
          domain: mesh.ashbyte.com
          locus: x707_x762
          tunnel_ipv4: 192.168.12.0/24
          tunnel_ipv6: fd86:ea04:1116::/64
          portbase: 4404
          publickey: ''
          privatekey: dev/x707_x762_priv
          route53: ZXHE
        hosts:
          AtomBattler.ashbyte.com:
            hostname: AtomBattler.ashbyte.com
            asn: 4200000000
            octet: 1
            local_ipv4:
            - 4.2.2.2/32
            - 8.8.8.8/32
            - fd86:ea04:1116::1/128
            local_ipv6: []
            public_key: ''
            local_networks: ''
            public_key_file: dev/example_endpoint_pub
            private_key_file: dev/example_endpoint_priv
            uuid: aee8a79f-c608-4fe9-8484-cdef6911366f
            publickey: ''

## Host configuration Documents

        host:
          cmdfping: /usr/sbin/fping
          hostname: oob.x707.erickson.lol
          interface_outbound: ''
          interface_public: enp6s18
          interface_trust: enp6s19
          interface_trust_ip: ''
          private_key_file: /etc/wireguard/x707_priv
          public_key_file: /etc/wireguard/x707_pub
          uuid: 2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d
        site:
          locus: x707
          public_key: O1wiV9r1DhBParqOUYBXD2OanH4X8TVcB75J/zi6LB0=

## Host Publishing Records



# Encoded Site DNS

This is a short JSON document which includes specific information. It currently
only uses two fields, 'locus', and 'publickey'.

Locus is for convenience and readability, the publickey is used for sending messages
to the site controller.

    {'locus': 'x707', 'publickey': 'O1wiV9r1DhBParqOUYBXD2OanH4X8TVcB75J/zi6LB0='}

