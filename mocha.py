from struct import pack,unpack

class i32():
    mask = 0xffffffff
    def __init__(self,x):
        if isinstance(x,i32):
            self._v = x._v&self.mask
        else:
            self._v = x&self.mask
    def __add__(self,x):
        if isinstance(x,i32):
            return i32(self._v+x._v)
        else:
            return i32(self._v+x)
    def __xor__(self,x):
        if isinstance(x,i32):
            return i32(self._v^x._v)
        else:
            return i32(self._v^x)
    def __or__(self,x):
        if isinstance(x,i32):
            return i32(self._v|x._v)
        else:
            return i32(self._v|x)
    def __and__(self,x):
        if isinstance(x,i32):
            return i32(self._v&x._v)
        else:
            return i32(self._v&x)
    def __lshift__(self,x):
        return i32(self._v<<x)
    def __rshift__(self,x):
        return i32(self._v>>x)
    def hex(self):
        return hex(self._v)
    def __repr__(self):
        return repr(self._v)

def block_ctr(k,ctr):
    assert len(k) == 0x2c

    key = [0]*0x40
    for i,c in enumerate(b"expand 32-byte k"):
        key[i] = c
    for i in range(32):
        key[i+0x10] = k[i]
    write_i32(key,ctr,0x30)
    for i in range(12):
        key[i+0x34] = k[i+32]

    return key

def read_i32(buff,i):
    return unpack("<I", bytes(buff[i:i+4]))[0]
def write_i32(buff,v,i):
    for j,b in enumerate(pack("<I",v)):
        buff[i+j] = b

def mocha_hash(key,nrounds=0x14):
    assert len(key) == 0x40

    out_i32 = [0]*0x10
    for i in range(0x10):
        out_i32[i] = i32(read_i32(key,i*4))

    lr = out_i32[11]
    sb = out_i32[15]
    r8 = out_i32[7]
    r5 = out_i32[0]
    r0 = out_i32[1]
    r6 = out_i32[10]
    sl = out_i32[6]
    ip = out_i32[5]
    fp = out_i32[8]
    t_0x34 = out_i32[2]
    t_0x3c = out_i32[3]
    t_0x38 = out_i32[14]
    t_0x30 = out_i32[9]
    t_0x28 = out_i32[13]
    t_0x24 = out_i32[12]
    t_0x2c = out_i32[4]
    ind = nrounds
    while ind > 0:
        r0 = r0 + ip
        r1 = t_0x28 ^ r0
        r2 = t_0x30
        r2 = r2 + (r1 >> 0x10 | r1 << 0x10)
        r3 = r2 ^ ip
        t_0x1c = r3
        ip = sb
        r0 = r0 + (r3 >> 0x14 | r3 << 0xc)
        t_0x18 = r0
        r0 = r0 ^ (r1 >> 0x10 | r1 << 0x10)
        t_0x28 = r0
        r1 = t_0x38
        r4 = r2 + (r0 >> 0x18 | r0 << 8)
        r0 = t_0x34
        r2 = r8
        t_0x8 = r4
        r0 = r0 + sl
        r3 = r1 ^ r0
        r1 = r6 + (r3 >> 0x10 | r3 << 0x10)
        t_0x10 = r1
        r1 = r1 ^ sl
        t_0xc = r1
        r8 = r0 + (r1 >> 0x14 | r1 << 0xc)
        r0 = t_0x2c
        r1 = t_0x24
        sl = r8 ^ (r3 >> 0x10 | r3 << 0x10)
        r3 = r0 + r5
        r5 = r1 ^ r3
        r6 = fp + (r5 >> 0x10 | r5 << 0x10)
        fp = r6 ^ r0
        r0 = r3 + (fp >> 0x14 | fp << 0xc)
        t_0x14 = r0
        sb = r0 ^ (r5 >> 0x10 | r5 << 0x10)
        r0 = t_0x3c
        r5 = r6 + (sb >> 0x18 | sb << 8)
        r6 = r2 + r0
        r3 = ip ^ r6
        fp = r5 ^ (fp >> 0x14 | fp << 0xc)
        ip = lr + (r3 >> 0x10 | r3 << 0x10)
        lr = ip ^ r2
        r6 = r6 + (lr >> 0x14 | lr << 0xc)
        r0 = r6 + (fp >> 0x19 | fp << 7)
        r1 = r0 ^ (sl >> 0x18 | sl << 8)
        r2 = r4 + (r1 >> 0x10 | r1 << 0x10)
        fp = r2 ^ (fp >> 0x19 | fp << 7)
        r0 = r0 + (fp >> 0x14 | fp << 0xc)
        t_0x3c = r0
        r0 = r0 ^ (r1 >> 0x10 | r1 << 0x10)
        r1 = r0 >> 0x18 | r0 << 8
        r0 = r2 + (r0 >> 0x18 | r0 << 8)
        t_0x30 = r0
        r0 = r0 ^ (fp >> 0x14 | fp << 0xc)
        t_0x38 = r1
        r1 = r6 ^ (r3 >> 0x10 | r3 << 0x10)
        r0 = r0 >> 0x19 | r0 << 7
        r6 = t_0x28
        t_0x2c = r0
        r0 = ip + (r1 >> 0x18 | r1 << 8)
        r2 = r0 ^ (lr >> 0x14 | lr << 0xc)
        r3 = r8 + (r2 >> 0x19 | r2 << 7)
        r6 = r3 ^ (r6 >> 0x18 | r6 << 8)
        r5 = r5 + (r6 >> 0x10 | r6 << 0x10)
        r2 = r5 ^ (r2 >> 0x19 | r2 << 7)
        r3 = r3 + (r2 >> 0x14 | r2 << 0xc)
        t_0x34 = r3
        r3 = r3 ^ (r6 >> 0x10 | r6 << 0x10)
        fp = r5 + (r3 >> 0x18 | r3 << 8)
        r6 = r3 >> 0x18 | r3 << 8
        r2 = fp ^ (r2 >> 0x14 | r2 << 0xc)
        r3 = t_0xc
        t_0x28 = r6
        r8 = r2 >> 0x19 | r2 << 7
        r2 = t_0x10
        r6 = t_0x18
        r2 = r2 + (sl >> 0x18 | sl << 8)
        r3 = r2 ^ (r3 >> 0x14 | r3 << 0xc)
        r6 = r6 + (r3 >> 0x19 | r3 << 7)
        r5 = r6 ^ (sb >> 0x18 | sb << 8)
        r4 = r0 + (r5 >> 0x10 | r5 << 0x10)
        r3 = r4 ^ (r3 >> 0x19 | r3 << 7)
        r0 = r6 + (r3 >> 0x14 | r3 << 0xc)
        r6 = r0 ^ (r5 >> 0x10 | r5 << 0x10)
        lr = r4 + (r6 >> 0x18 | r6 << 8)
        r5 = r6 >> 0x18 | r6 << 8
        r3 = lr ^ (r3 >> 0x14 | r3 << 0xc)
        r6 = t_0x8
        t_0x24 = r5
        sl = r3 >> 0x19 | r3 << 7
        r3 = t_0x1c
        r3 = r6 ^ (r3 >> 0x14 | r3 << 0xc)
        r6 = t_0x14
        r6 = r6 + (r3 >> 0x19 | r3 << 7)
        r1 = r6 ^ (r1 >> 0x18 | r1 << 8)
        r2 = r2 + (r1 >> 0x10 | r1 << 0x10)
        r3 = r2 ^ (r3 >> 0x19 | r3 << 7)
        r5 = r6 + (r3 >> 0x14 | r3 << 0xc)
        r1 = r5 ^ (r1 >> 0x10 | r1 << 0x10)
        r6 = r2 + (r1 >> 0x18 | r1 << 8)
        sb = r1 >> 0x18 | r1 << 8
        r1 = r6 ^ (r3 >> 0x14 | r3 << 0xc)
        ip = r1 >> 0x19 | r1 << 7

        ind -= 2

    out_i32[4] = t_0x2c
    out_i32[12] = t_0x24
    out_i32[13] = t_0x28
    out_i32[9] = t_0x30
    out_i32[2] = t_0x34
    out_i32[14] = t_0x38
    out_i32[3] = t_0x3c
    out_i32[11] = lr
    out_i32[15] = sb
    out_i32[7] = r8
    out_i32[0] = r5
    out_i32[1] = r0
    out_i32[10] = r6
    out_i32[6] = sl
    out_i32[5] = ip
    out_i32[8] = fp

    for i in range(0x10):
        out_i32[i] += i32(read_i32(key,i*4))

    out = [0]*0x40
    for i,v in enumerate(out_i32):
        write_i32(out,v._v,i*4)

    return out

def xor(b1,b2):
    return [ a^b for a,b in zip(b1,b2) ]

def mocha_decrypt(buff,key):
    out = []
    for i in range(0,len(buff),0x40):
        k = mocha_hash(block_ctr(key,i//0x40))
        out += xor(buff[i:i+0x40],k)

    return out
