#!/usr/bin/env python

import zlib
from os import stat
from sys import argv
from glob import fnmatch
from struct import unpack
from zipfile import ZipFile
from Crypto.Cipher import AES
from Crypto.Util import Counter
from mocha import mocha_decrypt

# hardcoded keys from the binary
aes_key = [236, 117, 47, 146, 173, 127, 77, 82, 188, 140, 238, 196, 103, 143, 251, 7, 40, 176, 77, 23, 206, 7, 72, 182, 142, 125, 214, 171, 82, 177, 34, 59]
mocha_key = [147, 209, 157, 175, 59, 89, 70, 1, 160, 202, 56, 12, 72, 98, 194, 208, 75, 103, 39, 106, 177, 4, 73, 197, 134, 218, 96, 14, 229, 206, 174, 244, 64, 241, 15, 239, 30, 8, 72, 163, 186, 128, 228, 253]

def decrypt_da2(filepath, book_key):
    file_size = stat(filepath).st_size
    f = open(filepath, "rb")
    tmp = f.read(16)
    if not tmp.startswith(b"mda2"):
        return None
    other_size = unpack("<I", f.read(4))[0] # what's this?
    f.read(8)
    body_size = unpack("<I", f.read(4))[0]
    header_end = file_size - other_size - body_size
    if header_end < 0:
        return None
    tmp = unpack("<I", f.read(4))[0]
    if tmp != 0x2c:
        return None
    enc_file_key = f.read(0x2c)
    file_key = decrypt_file_key(enc_file_key, book_key)

    f.read(4)
    ct_sizes = []
    pos = 0x54
    while pos < header_end:
        ct_sizes.append(unpack("<I", f.read(4))[0])
        f.read(4)
        pos += 8
    ct = f.read(sum(ct_sizes))
    f.close()

    pt = mocha_decrypt(ct, file_key)
    pos = 0
    pt_deflate = b""
    for ct_size in ct_sizes:
        try:
            pt_deflate += deflate(pt[pos:pos+ct_size])
            pos += ct_size
        except:
            return None

    fileout = filepath + ".plaintext"
    f = open(fileout, "wb")
    f.write(pt_deflate)
    f.close()
    return fileout


def decrypt_file_key(ct, book_key):
    ctr = Counter.new(128, initial_value=int(bytes(book_key[16:]).hex(),16))
    cipher = AES.new(bytes(book_key[:16]), AES.MODE_CTR, counter=ctr)
    return list(cipher.decrypt(ct))

simplify = decrypt_file_key

def deflate(x):
    return zlib.decompressobj(zlib.MAX_WBITS).decompress(bytes(x))

def extract_parameters(buff):
    # more arbitrary obfuscation
    buff = simplify(buff, aes_key)
    buff = [buff[i]^buff[i+1] for i in range(0,len(buff),2)]
    a1,b1,c1,a2,b2,c2 = unpack("<IIIIII", bytes(buff))
    return [a1*b1+c1, a2*b2+c2]

def generate_key(filepath, magic_offset):
    # The key is made up of various bytes in the file that are then
    # mochaed with an hardcoded key
    # To find these bytes start at the magic offset
    # Then, every 3 bytes (mod the length of the file) indicates
    # the position of the next key material byte
    file_size = stat(filepath).st_size
    f = open(filepath, "rb")
    tmp = f.read(16)
    if not tmp.startswith(b"mda2"):
        return None
    other_size = unpack("<I", f.read(4))[0] # what's this?
    f.read(8)
    body_size = unpack("<I", f.read(4))[0]
    header_end = file_size - other_size - body_size
    if header_end < 0:
        return None
    f.read(header_end - 32)

    # file seeks would be better for mem
    content = f.read(body_size)
    key_mat = []
    for i in range(0x20):
        pos = (i*3+magic_offset)%body_size
        pos = unpack("<I", content[pos:pos+3]+b"\x00")[0]%body_size
        key_mat += [content[pos]]
    return mocha_decrypt(key_mat, mocha_key)

def decrypt_epubx(epubx_path):
    with ZipFile(epubx_path, 'r') as myzip:
        param_files = fnmatch.filter(myzip.namelist(), "mash")
        if len(param_files) == 0:
            param_files = fnmatch.filter(myzip.namelist(), "**/mash")
        if len(param_files) == 0:
            print("Warn: mash file not found. Ebook may be in different format. Resorting to bruteforcing magic offsets up to 2^16")
            magic_offsets = range(2**16)
        else:
            if len(param_files) > 1:
                print(f"Warn: more than one mash file found, using {param_files[0]}")
            magic_offsets = extract_parameters(myzip.open(param_files[0]).read(0x30))

        for da2_path in fnmatch.filter(myzip.namelist(), "**/aText.dat"):
            print(f"Found da2 file {da2_path}")
            myzip.extract(da2_path)
            print("Attempting decryption (may take a while for large books due to slow implementation)")
            for magic_offset in magic_offsets:
                key = generate_key(da2_path, magic_offset)
                fout = decrypt_da2(da2_path, key)
                if fout is not None:
                   print(f"Decrypted to {fout}")
                   break
            else:
               print("Unable to decrypt :(")

if len(argv) > 1:
    decrypt_epubx(argv[1])
else:
    print(f"Usage: {argv[0]} mybook.epubx")
