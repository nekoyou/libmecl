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

# output from getKey1()
book_key = [0]*32

def decrypt_da2(filename):
    file_size = stat(filename).st_size
    f = open(filename, "rb")
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
        pt_deflate += deflate(pt[pos:pos+ct_size])
        pos += ct_size

    fileout = filename + ".plaintext"
    f = open(fileout, "wb")
    f.write(pt_deflate)
    f.close()
    return fileout


def decrypt_file_key(ct, book_key):
    ctr = Counter.new(128, initial_value=int(bytes(book_key[16:]).hex(),16))
    cipher = AES.new(bytes(book_key[:16]), AES.MODE_CTR, counter=ctr)
    return list(cipher.decrypt(ct))

def deflate(x):
    return zlib.decompressobj(zlib.MAX_WBITS).decompress(bytes(x))

def decrypt_epubx(epubx_path):
    with ZipFile(epubx_path, 'r') as myzip:
        for da2_path in fnmatch.filter(myzip.namelist(), "**/aText.dat"):
            print(f"Found da2 file {da2_path}")
            myzip.extract(da2_path)
            print(f"Attempting decryption (may take a while for large books due to slow implementation)")
            fout = decrypt_da2(da2_path)
            if fout is not None:
               print(f"Decrypted to {fout}")
            else:
               print("Unable to decrypt :(")

if len(argv) > 1:
    decrypt_epubx(argv[1])
else:
    print(f"Usage: {argv[0]} mybook.epubx")
