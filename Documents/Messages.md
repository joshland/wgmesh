
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



### Host Rekey

        {'uuid': '<uuid>', 'command': 'rekey', 'publickey': '', 'newpublickey': '' }

new payload published under new key, immediately published
    
