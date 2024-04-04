
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
    
## Site -> Host Deployment Records

        core = {
           'asn':      me.asn,
            'site':     site.domain,
            'octet':    me.octet,
            'portbase': site.portbase,
            'remote':   str(site.ipv6),
            'hosts': {},
            }

        logger.trace(f'Deploy Host: {me.uuid}')
        for h in hosts:
            if me.uuid == h.uuid: continue
            logger.trace(f'Add host: {h.uuid}')
            logger.trace(f'IPv4: {h.local_ipv4}')
            logger.trace(f'IPv6: {h.local_ipv6}')
            core['hosts'][h.hostname] = { 
                'key': h.public_key,
                'asn': h.asn,
                'localport': h.endport(),
                'remoteport': myport,
                'remote': ','.join([ str(x) for x in h.local_ipv4 + h.local_ipv6 if str(x) > '' ]),
                }
            continue


        {

