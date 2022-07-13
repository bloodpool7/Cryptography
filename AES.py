aes_sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

reverse_aes_sbox = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
]
def string_to_hex(instring):
  return "".join(format(int(c,16), '02x') for c in [hex(ord(x)) for x in instring])

def hex_to_string(instring):
  if (instring[0:2] == "0x"):
    instring = instring[2:]
  hex_list = [instring[x:x+2] for x in range(0, len(instring), 2)]
  return "".join(chr(int(x, 16)) for x in hex_list)

def xor_hex_strings(message, key):
    return hex(int(message, 16) ^ int(key, 16))[2:]

def xor_hex_strings_samelen(message, key):
    output = ""
    for i in range(len(message)):
        output += hex(int(message[i], 16) ^ int(key[i], 16))[2:]
    return output

def bytes_to_matrix(block):
  list_of_bytes = [block[x:x+2] for x in range(0, len(block), 2)]
  matrix = []
  for i in range(4):
    row = []
    for j in range(0, 16, 4):
      row.append(list_of_bytes[i+j])
    matrix.append(row)
  return matrix 

def matrix_to_bytes(matrix):
  out_string = ""
  for i in range(4):
    for list in matrix:
      out_string += list[i]
  return out_string

def lookup(byte):
  if len(byte) == 1:
    byte = "0" + byte
  x = int(byte[0], 16)
  y = int(byte[1], 16)
  out = hex(aes_sbox[x][y])[2:]
  return out if len(out) > 1 else "0"+out

def reverse_lookup(byte):
  x = int(byte[0], 16)
  y = int(byte[1], 16)
  out = hex(reverse_aes_sbox[x][y])[2:]
  return out if len(out) > 1 else "0"+out
  
def rotate_row_left(row, n = 1):
  return row[n:] + row[:n]

def multiply_by_2(byte):
  byte_int = int(byte, 16)
  byte_int <<= 1
  if byte_int >= 256:
    byte_int ^= 0x11b
  byte_hex = hex(byte_int)[2:]
  return byte_hex if len(byte_hex) > 1 else "0" + byte_hex

def multiply_by_3(byte):
  byte_2 = multiply_by_2(byte)
  byte_3 = hex(int(byte_2, 16) ^ int(byte, 16))[2:]
  return byte_3 if len(byte_3) > 1 else "0" + byte_3

def mix_column(column):
  out_col = [hex(int(multiply_by_2(column[0]), 16) ^ int(multiply_by_3(column[1]), 16) ^ int(column[2], 16) ^ int(column[3], 16))[2:],
             hex(int(multiply_by_2(column[1]), 16) ^ int(multiply_by_3(column[2]), 16) ^ int(column[0], 16) ^ int(column[3], 16))[2:],
             hex(int(multiply_by_2(column[2]), 16) ^ int(multiply_by_3(column[3]), 16) ^ int(column[0], 16) ^ int(column[1], 16))[2:],
             hex(int(multiply_by_2(column[3]), 16) ^ int(multiply_by_3(column[0]), 16) ^ int(column[1], 16) ^ int(column[2], 16))[2:]]

  for i in range(len(out_col)):
    if len(out_col[i]) == 1:
        out_col[i] = "0" + out_col[i]

  return out_col
  
def unmix_column(column):
  return mix_column(mix_column(mix_column(column)))

def expand_key(key, rounds):
    rcon = [["1", "0", "0","0"]]
    for i in range(1, rounds-1):
        rcon.append([hex(int(rcon[-1][0], 16) * 2)[2:], "0", "0", "0"])
        if int(rcon[-1][0], 16) > 0x80:
            rcon[-1][0] = hex(int(rcon[-1][0], 16) ^ 0x11b)[2:]
    
    key = break_into_words(key)
    words = []
    for i in range(4 * rounds):
        if i < 4:
            words.append(key[i])
            continue
        elif i % 4 == 0:
            rotated_word = rotate_row_left(words[i-1])
            subbed_word = [lookup(x) for x in rotated_word]
            rcon_applied = [xor_hex_strings(rcon[i//4 - 1][j], x) if len(xor_hex_strings(rcon[i//4 - 1][j], x)) == 2 else "0" + xor_hex_strings(rcon[i//4 - 1][j], x) for j, x in enumerate(subbed_word)]
            final_word = [xor_hex_strings(words[i-4][j], x) if len(xor_hex_strings(words[i-4][j], x)) == 2 else "0" + xor_hex_strings(words[i-4][j], x) for j, x in enumerate(rcon_applied)]
            words.append(final_word)
        else:
            words.append([xor_hex_strings(words[i-1][j], x) if len(xor_hex_strings(words[i-1][j], x)) == 2 else "0" + xor_hex_strings(words[i-1][j], x) for j, x in enumerate(words[i-4])])

    final_words = ["".join(["".join(words[i]) for i in range(len(words))][i:i+4]) for i in range(0, len(["".join(words[i]) for i in range(len(words))]), 4)]
    return final_words

def break_into_words(key):
    list_of_bytes = [key[x:x+2] for x in range(0, len(key), 2)]
    output = []
    for i in range(0, len(list_of_bytes), 4):
        output.append(list_of_bytes[i:i+4])
    return output

def xor_byte_matrices(matrix1, matrix2):
    out_matrix = []
    for i in range(len(matrix1)):
        out_matrix_row = []
        for j in range(len(matrix1[i])):
            final_byte = hex(int(matrix1[i][j], 16) ^ int(matrix2[i][j], 16))[2:]
            if len(final_byte) == 1:
                final_byte = "0" + final_byte
            out_matrix_row.append(final_byte)
        out_matrix.append(out_matrix_row)
    return out_matrix

def break_into_16_bytes(block):
    return [block[x:x+32] for x in range(0, len(block), 32)]

def encrypt(block, key):
    keys = expand_key(key, 11)
    key_matricies = [bytes_to_matrix(x) for x in keys]
    blocks = break_into_16_bytes(block)
    
    encrypted_blocks = []
    for block1 in blocks:
        state = bytes_to_matrix(block1)

        for i in range(10):
            if i != 9:
                state = xor_byte_matrices(state, key_matricies[i])
                state = [[lookup(x) for x in y] for y in state]
                state = [rotate_row_left(row, i) for i, row in enumerate(state)]
                for j in range(4):
                    column = []
                    for row in state:
                        column.append(row[j])
                    column = mix_column(column)
                    for k in range(4):
                        state[k][j] = column[k]
            else:
                state = xor_byte_matrices(state, key_matricies[i])
                state = [[lookup(x) for x in y] for y in state]
                state = [rotate_row_left(row, i) for i, row in enumerate(state)]

        final_state = matrix_to_bytes(xor_byte_matrices(state, key_matricies[10]))
        encrypted_blocks.append(final_state)

    ciphertext = "".join(encrypted_blocks)
    return ciphertext

def decrypt(block, key):
    keys = expand_key(key, 11)
    key_matricies = [bytes_to_matrix(x) for x in keys]
    blocks = break_into_16_bytes(block)

    decrypted_blocks = []
    for block1 in blocks:
        state = bytes_to_matrix(block1)

        for i in range(10, 0, -1):
            if i != 10:
                state = xor_byte_matrices(state, key_matricies[i])
                for j in range(4):
                    column = []
                    for row in state:
                        column.append(row[j])
                    column = unmix_column(column)
                    for k in range(4):
                        state[k][j] = column[k]
                state = [rotate_row_left(row, -j) for j, row in enumerate(state)]
                state = [[reverse_lookup(x) for x in y] for y in state]
            else:
                state = xor_byte_matrices(state, key_matricies[i])
                state = [rotate_row_left(row, -i) for i, row in enumerate(state)]
                state = [[reverse_lookup(x) for x in y] for y in state]

        final_state = matrix_to_bytes(xor_byte_matrices(state, key_matricies[0]))
        decrypted_blocks.append(final_state)
    
    plaintext = "".join(decrypted_blocks)
    return plaintext

def encrypt_cbc(msg, key, iv):
    blocks = break_into_16_bytes(msg)

    if len(blocks[-1]) < 32:
        padded_number = str((32-len(blocks[-1]))//2)
        for i in range((32-len(blocks[-1]))//2):
            blocks[-1] += hex(ord(padded_number if len(padded_number) == 1 else padded_number[1:]))[2:]

    prev_state = ""
    ciphertext = [iv]
    for i in range(len(blocks)):
        if i == 0:
            prev_state = encrypt(xor_hex_strings_samelen(blocks[i], iv), key)
            ciphertext.append(prev_state)
        else:
            ciphertext.append(encrypt(xor_hex_strings_samelen(blocks[i], prev_state), key))
            prev_state = encrypt(xor_hex_strings_samelen(blocks[i], prev_state), key)
    
    return "".join(ciphertext)

def decrypt_cbc(cipher, key):
    blocks = break_into_16_bytes(cipher)
    for i in range(len(blocks)):
        if len(blocks[i]) < 32:
            extra = len(blocks[i])+1
            for j in range(32 - len(blocks[i])):
                blocks[i] += "0"
    plaintext = []
    for i in range(1, len(blocks)):
        plaintext.append(xor_hex_strings_samelen(decrypt(blocks[i], key), blocks[i-1]))
    
    return "".join(plaintext)

def encrypt_ctr(plaintext, key, iv):
    blocks = break_into_16_bytes(plaintext)

    if len(blocks[-1]) < 32:
        padded_number = str((32-len(blocks[-1]))//2)
        for i in range((32-len(blocks[-1]))//2):
            blocks[-1] += hex(ord(padded_number if len(padded_number) == 1 else padded_number[1:]))[2:]

    ciphertext = [iv]
    for i in range(len(blocks)):
        encrypted_iv = encrypt(hex(int(iv, 16) + i)[2:], key)
        ciphertext.append(xor_hex_strings_samelen(encrypted_iv, blocks[i]))

    return "".join(ciphertext)

def decrypt_ctr(ciphertext, key):
    blocks = break_into_16_bytes(ciphertext)
    extra = 0
    for i in range(len(blocks)):
        if len(blocks[i]) < 32:
            extra = len(blocks[i])+1
            for j in range(32 - len(blocks[i])):
                blocks[i] += "0"
    plaintext = []
    for i in range(1, len(blocks)):
        decrypted_iv = encrypt(hex(int(blocks[0], 16) + (i-1))[2:], key)
        plaintext.append(xor_hex_strings_samelen(decrypted_iv, blocks[i]))
    
    plaintext[-1] = plaintext[-1][:extra] if extra != 0 else plaintext[-1]
    return "".join(plaintext)

if __name__ == "__main__":
    key = string_to_hex("this a test key!")
    message = string_to_hex("hello world this is a test message lets hope its not a multiple of 16")
    iv = string_to_hex("this is a random")

    ct = encrypt_ctr(message, key, iv)
    print(hex_to_string(ct))
    pt = hex_to_string(decrypt_ctr(ct, key))
    print(pt)
