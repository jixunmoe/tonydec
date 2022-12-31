#!/usr/bin/env python3

tonyenc_header = bytes([
    0x66, 0x88, 0xff, 0x4f,
    0x68, 0x86, 0x00, 0x56,
    0x11, 0x61, 0x16, 0x18,
])

tonyenc_key = bytes([
    0x9f, 0x49, 0x52, 0x00,
    0x58, 0x9f, 0xff, 0x23,
    0x8e, 0xfe, 0xea, 0xfa,
    0xa6, 0x33, 0xf3, 0xc6,
])


def decrypt_content(data: bytes, header=tonyenc_header, key=tonyenc_key):
    if not data.startswith(header):
        return None

    data = bytearray(data[len(header):])
    data_len = len(data)
    p = 0
    for i in range(1, data_len, 2):
        p = (p + key[p] + i) % len(key)
        data[i] = data[i] ^ key[p] ^ 0b1111_1111

    return data


def decrypt_file(input_path: str, output_path: str, header=tonyenc_header, key=tonyenc_key):
    import os
    import shutil
    print(f'Processing file: {input_path}...', end='')
    input_content = None
    with open(input_path, 'rb') as f:
        input_content = f.read()
    decrypted_content = decrypt_content(input_content, header, key)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if decrypted_content is None:
        print('not tonyenc encrypted, copy as it is...')
        shutil.copyfile(input_path, output_path)
    else:
        with open(output_path, 'wb') as f:
            f.write(decrypted_content)
        print('ok!')


def recurse_decrypt(input_dir, output_dir, header=tonyenc_header, key=tonyenc_key):
    from os import listdir, path
    for f in listdir(input_dir):
        input_path = path.join(input_dir, f)
        output_path = path.join(output_dir, f)

        if path.isfile(input_path):
            decrypt_file(input_path, output_path, header, key)
        elif path.isdir(input_path):
            recurse_decrypt(input_path, output_path, header, key)


def usage():
    print('''
    tonydec - a simple decoder for tonyenc.

    Usage:
      tonydec <input_dir> <output_dir>
    ''')


def main():
    from sys import argv

    if len(argv) != 3:
        usage()
        return

    [_, input_dir, output_dir] = argv
    recurse_decrypt(input_dir, output_dir)


if __name__ == '__main__':
    main()
