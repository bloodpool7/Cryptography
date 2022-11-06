from itertools import combinations
from AES import * 

if __name__ == "__main__":
    f = open("ciphers.txt", "r")
    ciphers = f.read().split("\n")
    for cipher in ciphers:
        print(hex_to_string(cipher))
    ciphers = [bytes.fromhex(x)[:83] for x in ciphers]
    xors = dict([(x, list()) for x in range(len(ciphers))])
    for i, j in combinations(ciphers, 2):
        xors[ciphers.index(i)].append(bytes.fromhex(xor_hex_strings_samelen(i.hex(), j.hex())))
        xors[ciphers.index(j)].append(bytes.fromhex(xor_hex_strings_samelen(i.hex(), j.hex())))
    
    key = [b"" for x in range(83)]
    
    for i in xors:
        confidences = {}
        for ct in xors[i]:
            for j in range(len(ct)):
                if ct[j] > 0x40:
                    confidences[j] = 1 if j not in confidences else confidences[j] + 1
        for index in confidences:
            if confidences[index] >= 7:
                key[index] = bytes([ciphers[i][index] ^ 0x20])
    
    def recompute_key(inkey, message, target):
        outkey = inkey
        if len(message) != len(target):
            raise Exception("Cannot enter two messages of differing lengths! The difference in lengths are: " + str(len(message) - len(target)))
        error = []
        for i in range(len(message)):
            if message[i] != target[i]:
                error.append(i)
        for index in error:
            ctbyte = bytes([ord(message[index]) ^ int.from_bytes(inkey[index], "big")])
            outkey[index] = bytes([int.from_bytes(ctbyte, "big") ^ ord(target[index])])
        return outkey

    key = [b"\x00" if x == b"" else x for x in key]
    fullkey = b"".join(key)

    wrong_message = "Thm secuet mesæage is  Whtn usa|w wsstrªíÌ cipher  nevir use the key more than once"
    key = recompute_key(key, wrong_message, "The secret mesæage is  Whtn usa|w wsstrªíÌ cipher  nevir use the key more than once")
    fullkey = b"".join(key)

    wrong_message = "A (private-key¼  encrcpti~n sc`w}e6 tatªÿ3 algorethms  namely a procedure for gene"
    key = recompute_key(key, wrong_message, "A (private-key¼  encryption scheme6 tatªÿ3 algorithms  namely a procedure for gene")
    fullkey = b"".join(key)

    wrong_message = "We can factor áhe number 15 with qc2ntu¢¬Âomputers. We,can also factor the number 1"
    key = recompute_key(key, wrong_message, "We can factor the number 15 with quantum computers. We can also factor the number 1")
    fullkey = b"".join(key)

    for i in range(11):
        print(hex_to_string(xor_hex_strings_samelen(fullkey.hex(), ciphers[i].hex())))
    #print(hex_to_string(xor_hex_strings_samelen(fullkey.hex(), ciphers[-1].hex())))