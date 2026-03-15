import z3, time

from pathlib import Path
import sys

# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from AES import supreme_encryption
N = 20 # number of plaintext-ciphetext pairs used
SECRET_KEY = "6cebfd76208afcd8a80501071a22c835"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 2, "")
    pairs.append((bytes.fromhex(pt), bytes.fromhex(ct)))
print('Using N',N)

sbox=[
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# pack sbox into 2048-bit table, entry i in low bits of byte i
T_int=0
for i,v in enumerate(sbox):
    T_int |= v << (8*i)
T = z3.BitVecVal(T_int, 2048)

def z_sbox(x8):
    # x8 is BitVec(8)
    sh = z3.ZeroExt(2040, x8) << 3  # *8
    return z3.Extract(7,0, z3.LShR(T, sh))

# AES operations

def z_xtime(b):
    msb=z3.Extract(7,7,b)
    shifted=(b<<1)
    return z3.If(msb==z3.BitVecVal(1,1), shifted ^ z3.BitVecVal(0x1b,8), shifted)

def z_mul(b,by):
    if by==1: return b
    if by==2: return z_xtime(b)
    if by==3: return z_xtime(b)^b
    raise ValueError

def z_shift_rows(st):
    out=st.copy()
    for r in range(4):
        row=[st[4*c+r] for c in range(4)]
        row=row[r:]+row[:r]
        for c in range(4): out[4*c+r]=row[c]
    return out

def z_mix_columns(st):
    out=st.copy()
    for c in range(4):
        a=[st[4*c+r] for r in range(4)]
        out[4*c+0]=z_mul(a[0],2)^z_mul(a[1],3)^a[2]^a[3]
        out[4*c+1]=a[0]^z_mul(a[1],2)^z_mul(a[2],3)^a[3]
        out[4*c+2]=a[0]^a[1]^z_mul(a[2],2)^z_mul(a[3],3)
        out[4*c+3]=z_mul(a[0],3)^a[1]^a[2]^z_mul(a[3],2)
    return out

# key expansion for 2 rounds

def z_expand_key_2r(K):
    w=[K[i:i+4] for i in range(0,16,4)]
    def g(word,rc):
        # RotWord then SubWord
        tmp=[word[1],word[2],word[3],word[0]]
        tmp=[z_sbox(x) for x in tmp]
        tmp[0]=tmp[0]^z3.BitVecVal(rc,8)
        return tmp
    def xw(a,b):
        return [a[i]^b[i] for i in range(4)]
    w4=xw(w[0], g(w[3],0x01))
    w5=xw(w[1], w4)
    w6=xw(w[2], w5)
    w7=xw(w[3], w6)
    w8=xw(w4, g(w7,0x02))
    w9=xw(w5, w8)
    w10=xw(w6, w9)
    w11=xw(w7, w10)
    W=w+[w4,w5,w6,w7,w8,w9,w10,w11]
    k0=sum(W[0:4],[])
    k1=sum(W[4:8],[])
    k2=sum(W[8:12],[])
    return k0,k1,k2


def z_aes2_enc(pt,K):
    st=[z3.BitVecVal(b,8) for b in pt]
    k0,k1,k2=z_expand_key_2r(K)
    st=[st[i]^k0[i] for i in range(16)]
    st=[z_sbox(x) for x in st]
    st=z_shift_rows(st)
    st=z_mix_columns(st)
    st=[st[i]^k1[i] for i in range(16)]
    st=[z_sbox(x) for x in st]
    st=z_shift_rows(st)
    st=[st[i]^k2[i] for i in range(16)]
    return st

# concrete verifier (fast)

def aes2_encrypt_block(pt,key_bytes):
    # key_bytes: bytes length 16
    # implement same as previous
    def xtime(b):
        return ((b<<1)&0xff) ^ (0x1b if (b&0x80) else 0)
    def mul(b,by):
        if by==1: return b
        if by==2: return xtime(b)
        if by==3: return xtime(b)^b
    def sub_bytes(st):
        return [sbox[x] for x in st]
    def shift_rows(st):
        out=st.copy()
        for r in range(4):
            row=[st[4*c+r] for c in range(4)]
            row=row[r:]+row[:r]
            for c in range(4): out[4*c+r]=row[c]
        return out
    def mix_columns(st):
        out=st.copy();
        for c in range(4):
            a=[st[4*c+r] for r in range(4)]
            out[4*c+0]=mul(a[0],2)^mul(a[1],3)^a[2]^a[3]
            out[4*c+1]=a[0]^mul(a[1],2)^mul(a[2],3)^a[3]
            out[4*c+2]=a[0]^a[1]^mul(a[2],2)^mul(a[3],3)
            out[4*c+3]=mul(a[0],3)^a[1]^a[2]^mul(a[3],2)
        return out
    def expand_key(key):
        kb=list(key)
        w=[kb[i:i+4] for i in range(0,16,4)]
        def rot(wd): return wd[1:]+wd[:1]
        def subw(wd): return [sbox[x] for x in wd]
        def g(wd,rc):
            t=subw(rot(wd)); t[0]^=rc; return t
        def xw(a,b): return [(a[i]^b[i])&0xff for i in range(4)]
        w4=xw(w[0],g(w[3],0x01)); w5=xw(w[1],w4); w6=xw(w[2],w5); w7=xw(w[3],w6)
        w8=xw(w4,g(w7,0x02)); w9=xw(w5,w8); w10=xw(w6,w9); w11=xw(w7,w10)
        W=w+[w4,w5,w6,w7,w8,w9,w10,w11]
        return sum(W[0:4],[]), sum(W[4:8],[]), sum(W[8:12],[])
    st=list(pt)
    k0,k1,k2=expand_key(key_bytes)
    st=[st[i]^k0[i] for i in range(16)]
    st=sub_bytes(st); st=shift_rows(st); st=mix_columns(st); st=[st[i]^k1[i] for i in range(16)]
    st=sub_bytes(st); st=shift_rows(st); st=[st[i]^k2[i] for i in range(16)]
    return bytes(st)

# solve with increasing pairs using QF_BV solver
K=[z3.BitVec(f'k{i}',8) for i in range(16)]
for npairs in [1,2,3]:
    s=z3.SolverFor('QF_BV')
    # no timeout; rely on tool limit
    for pt,ct in pairs[:npairs]:
        enc=z_aes2_enc(pt,K)
        for b,t in zip(enc,ct):
            s.add(b==z3.BitVecVal(t,8))
    print('checking with',npairs,'pairs')
    t0=time.time(); r=s.check(); t1=time.time(); print('  res',r,'time',t1-t0)
    if r==z3.sat:
        m=s.model(); key=bytes([m.evaluate(K[i]).as_long() for i in range(16)])
        print('  key',key.hex())
        # verify quickly on all 20 known pairs
        ok=True
        for pt,ct in pairs:
            if aes2_encrypt_block(pt,key)!=ct:
                ok=False
                break
        print('  verifies all pairs?',ok)
        if ok:
            break