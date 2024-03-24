## Quick Notes on the ed25519 Use


The intent is to encrypt all messages by the public keys.  Ultimately, the intent was/is to create an API which can
be trivially authenticated to using a known public key.  I haven't written this yet, but it should not be complicated.

Wireguard uses base64 endcoded ed25519 keys.  All of this tool is built upon those keys.  I haven't built a means of rotating
keys at this point.

The essentials:

Loading a key:

open(file).read() => base64 encoded string
base64.decode(string) => byte-string of the key
private_key_obj = nacl.public.PrivateKey('byte-string-from-key')

#### Example Use:


        import base64
        import nacl.utils
        from nacl.public import PrivateKey

        private_key = b'7a1aeST/1ZxpHstmYeX/D3QSfvDdFb/bKN+qjeUz1GI='
        public_key = b'Yj6WMUAVWk9WCwEUMZHHV0RgjmwhKSN7IMFkYJK4wQQ=\n'

        raw_pubkey  = base64.decodebytes(public_key)
        raw_privkey = base64.decodebytes(private_key)

        my_key =  PrivateKey(raw_privkey) # this object can be using in cryptographic operations


#### Cli Example

        >>> from nacl.utils import PrivateKey
        >>> from nacl.public import PrivateKey
        >>> print(PrivateKey.__doc__)

            Private key for decrypting messages using the Curve25519 algorithm.

            .. warning:: This **must** be protected and remain secret. Anyone who
                knows the value of your :class:`~nacl.public.PrivateKey` can decrypt
                any message encrypted by the corresponding
                :class:`~nacl.public.PublicKey`

            :param private_key: The private key used to decrypt messages
            :param encoder: The encoder class used to decode the given keys

            :cvar SIZE: The size that the private key is required to be
            :cvar SEED_SIZE: The size that the seed used to generate the
                             private key is required to be
            
        >>> PrivateKey.generate()
        <nacl.public.PrivateKey object at 0x7ff7e105d550>
        >>> m = PrivateKey.generate()
        >>> m.public_key
        <nacl.public.PublicKey object at 0x7ff7e0ea09b0>
        >>> m.public_key.encode()
        b'\xed\xadZy$\xff\xd5\x9ci\x1e\xcbfa\xe5\xff\x0ft\x12~\xf0\xdd\x15\xbf\xdb(\xdf\xaa\x8d\xe53\xd4b'
        >>> m.encode()
        b'b>\x961@\x15ZOV\x0b\x01\x141\x91\xc7WD`\x8el!)#{ \xc1d`\x92\xb8\xc1\x04'
        >>> base64.encodebytes(m.public_key.encode())
        b'7a1aeST/1ZxpHstmYeX/D3QSfvDdFb/bKN+qjeUz1GI=\n'
        >>> base64.encodebytes(m.encode())
        b'Yj6WMUAVWk9WCwEUMZHHV0RgjmwhKSN7IMFkYJK4wQQ=\n'

