from os import urandom
from AES import encrypt_ecb, decrypt_ecb, pad, unpad

def parse(input):
    return dict([x.split("=") for x in input.split("&")])

def profile_for(input):
    if "&" in input or "=" in input:
        raise ValueError("Cannot enter metacharacters")
    
    return f"email={input}&uid=10&role=user"

def encrypt_profile_for(input, key):
    profile = profile_for(input)

    return encrypt_ecb(pad(profile.encode("ascii").hex(), 16 - len(profile)%16), key)

def decrypt_profile(input, key):
    unencoded = bytes.fromhex(unpad(decrypt_ecb(input,key))).decode()

    return parse(unencoded)

wanted = b"admin\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"

email = "blahblu@u.com"

key = "c9bcf2d6e611f51b46a247a230ba7e44"

result = encrypt_profile_for(email, key)

final = result[:64] 

email2 = b"AAAAAAAAAA" + wanted

admin = encrypt_profile_for(email2.decode(), key)

adminblock = admin[32:64]

final += adminblock 

print(decrypt_profile(final, key))