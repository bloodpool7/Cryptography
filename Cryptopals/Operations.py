import base64

def base64_to_hex(input):
    output = base64.b64decode(input)
    output = output.hex()
    return output

def hex_to_base64(input):
    output = base64.b64encode(base64.b16decode(input.upper()))
    output = output.decode("ascii")
    return output

def string_to_hex(input):
    output = input.encode("ascii").hex()
    return output

def string_to_base64(input):
    output = input.encode("ascii")
    return base64.b64encode(output).decode("ascii")

def base64_to_string(input):
    output = base64.b64decode(input)
    outstring = ""
    for byte in output:
        outstring += chr(byte)
    return outstring

def hex_to_string(instring):
  if (instring[0:2] == "0x"):
    instring = instring[2:]
  hex_list = [instring[x:x+2] for x in range(0, len(instring), 2)]
  return "".join(chr(int(x, 16)) for x in hex_list)
    
def xor_hex_strings(string1, string2):
    output =  hex(int(string1, 16) ^ int(string2, 16))[2:]
    for i in range(len(string1) - len(output)):
        output = "0" + output
    return output

if __name__ == "__main__":
    pass

