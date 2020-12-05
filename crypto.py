#!/usr/bin/env python3

#
# Crypto Test
#

# Load Keys Alice and Bob
# Encrypt Message 1

import nacl, base64, sys
from curve25519 import *

import nacl.utils
from nacl.public import PrivateKey, Box

import hashlib, uuid

alice_file = open(sys.argv[1], 'r').read()
bob_file = open(sys.argv[1], 'r').read()

alice_code = base64.decodebytes(alice_file.encode('ascii'))
bob_code   = base64.decodebytes(bob_file.encode('ascii'))


Alice = PrivateKey(alice_code)
Bob   = PrivateKey(bob_code)
Alice_Pub = Alice.public_key
Bob_Pub   = Bob.public_key

Alice_Box = Box(Alice, Bob_Pub)
Bob_Box   = Box(Bob, Alice_Pub)

msg = b"The Humans Are Dead."

msg_hash = hashlib.sha384(msg).hexdigest()

print("Create Message from Alice to Bob")
from_alice_to_bob  = Alice_Box.encrypt(msg)

print("Create Message from Bob to Alice")
from_bob_to_alice  = Bob_Box.encrypt(msg)


print('Decode:')
alice_decode = Bob_Box.decrypt(from_bob_to_alice)
bob_decode = Alice_Box.decrypt(from_alice_to_bob)

if msg_hash == hashlib.sha384(alice_decode).hexdigest():
    print(f'Alice Hash Matched')
else:
    print(f'Mismatch: Alice')
    pass

if msg_hash == hashlib.sha384(bob_decode).hexdigest():
    print(f'Bob Hash Matched')
else:
    print(f'Mismatch: Bob')
    pass

print(f'Alice: {alice_decode}')
print(f'Bob: {bob_decode}')
