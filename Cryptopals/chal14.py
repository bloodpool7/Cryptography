import AES
from Operations import * 
from itertools import combinations
from os import urandom
from random import randint 

def oracle(input):
    key = "a3b67e3ce4acb04f46e14687dc28a343"
    unknown = base64_to_hex('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK''')
    prefix = AES.unpad(AES.decrypt_ecb("5ca13819f3a6f42faf2d9f01ab07e78b166fa590d4b9657b05360a724a67c8b5", "85715d2fea76c1aadc265dc4f0addf46"))
    plaintext = prefix+input+unknown
    return AES.encrypt_ecb(AES.pad(plaintext, (32-len(plaintext)%32)//2), key)

def discover_block_size(oracle):
    base_len = len(oracle(""))
    test_len = base_len 
    test = b""
    while test_len == base_len:
        test += b"A"
        test_len = len(oracle(test.hex()))

    return test_len - base_len

def discover_unknown(oracle):
    bs = discover_block_size(oracle)
    original = oracle("")
    other = oracle(b"A".hex())
    blocknum = 0
    length = 0
    for i in range(0, len(other), bs):
        if other[i:i+bs] != original[i:i+bs]:
            blocknum = i//bs
            break
    while oracle((b"A" * length).hex())[bs * blocknum: bs*blocknum + bs] != oracle((b"A" * (length + 1)).hex())[bs * blocknum: bs*blocknum + bs]:
        length += 1
    
    offset = b"A" * length
    secret_size = (len(oracle(offset.hex())) - (blocknum + 1) * bs)//2
    feed = b"A" * (secret_size - 1)
    recovered = b"R"
    blocknum += 1
    for i in range(1, 2):
        onebyteshort = feed[:-i] + recovered if i != 0 else feed + recovered
        print(len(onebyteshort))
        combos = {}
        index = blocknum * bs + len(feed) * 2 - bs
        for i in range(256):
            combos[bytes.fromhex(oracle((offset + onebyteshort + bytes([i])).hex())[index: index+bs])] = bytes([i])
        recovered += combos[bytes.fromhex(oracle((offset+onebyteshort).hex())[index:index+bs])]
        print(recovered)


discover_unknown(oracle)

