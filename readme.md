# libmecl
Reverse project for `libmecl.so` (MCBook). Currently only support encryption type 5 (AES + mocha).

## Usage
`./mecl.py mybook.epubx`

Example output:
```
Found da2 file 0001/Text/aText.dat
Attempting decryption (may take a while for large books due to slow implementation)
Decrypted to 0001/Text/aText.dat.plaintext
```

## Todo
- Test on more books.
- Support other encryption types.
- Support other book assets than text.
