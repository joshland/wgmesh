## Site Management

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
        hosts: {}

Host configuration file:

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

## Public DNS Messages

Example Site with locus 'test':

        {'locus': 'test', 'publickey': 'O1wiV9r1DhBParqOUYBXD2OanH4X8TVcB75J/zi6LB0='}

## Host -> Site Json Docs

Base 64 encoded json document

        {'publickey': 'bas64 host key', 'message': 'encrypted_payload'}

Encrypted Message document

        encrypted_payload = {
            'uuid': '2bd3a14d-9b3b-4f1a-9d88-e7c413cd6d8d',
            'public_key': 'o6I7hQanMRT1VRjD6kAEz7IDdiT3KVCw1vj1Z58lVkY=',
            'public_key_file': '/etc/wireguard/x707_pub',
            'private_key_file': '/etc/wireguard/x707_priv',
            'local_ipv4': 'oob.x707.ashbyte.com',
            'local_ipv6': '',
        }


## Host Records

