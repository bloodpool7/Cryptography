from Crypto.Hash import SHA256
from Crypto.Hash import SHA1;
from os import urandom

f = open("6.2.birthday.mp4", "rb")
encoded = f.read()
blocks_of_kbs = [encoded[x: x+1024] for x in range(0, len(encoded), 1024)]

blocks_of_kbs.reverse()
f.close()

for i in range(len(blocks_of_kbs)):
    hasher = SHA256.new(blocks_of_kbs[i])
    hashed = hasher.digest()
    if i != len(blocks_of_kbs) - 1:
        blocks_of_kbs[i+1] += hashed 
    else:
        print(hashed.hex())