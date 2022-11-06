from Operations import *

def xor_with_repeating_key(long, short):
    temp = short 
    final_short = "" 
    for i in range(len(long) // len(short)):
        final_short += temp 
    
    if len(final_short) < len(long):
        final_short += short[0:len(long) - len(final_short)]
    
    return xor_hex_strings(string_to_hex(long), string_to_hex(final_short))

if __name__ == "__main__":
    test = xor_with_repeating_key('''Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal''', "ICE")
