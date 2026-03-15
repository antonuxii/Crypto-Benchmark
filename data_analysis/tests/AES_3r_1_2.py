'''
Sample suffered sandbox timeouts. We run its code independently to test whether the sandbox timeout constraints were too tight.
We obtain the following output:

constraints 64
^CTIME 14750.196997880936
sat? unknown

Conclusion: Sample fails
'''

import z3, time

SBOX = [
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
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def sub_bytes(s):
    return bytes(SBOX[b] for b in s)

def shift_rows(s):
    a=list(s)
    out=a[:]
    out[1],out[5],out[9],out[13] = a[5],a[9],a[13],a[1]
    out[2],out[6],out[10],out[14] = a[10],a[14],a[2],a[6]
    out[3],out[7],out[11],out[15] = a[15],a[3],a[7],a[11]
    return bytes(out)

def xtime(b):
    b &= 0xff
    return ((b<<1)&0xff) ^ (0x1b if (b&0x80) else 0)

def mix_single_column(col):
    a0,a1,a2,a3=col
    t = a0 ^ a1 ^ a2 ^ a3
    u = a0
    b0 = a0 ^ t ^ xtime(a0 ^ a1)
    b1 = a1 ^ t ^ xtime(a1 ^ a2)
    b2 = a2 ^ t ^ xtime(a2 ^ a3)
    b3 = a3 ^ t ^ xtime(a3 ^ u)
    return [b0&0xff,b1&0xff,b2&0xff,b3&0xff]

def mix_columns(s):
    a=list(s)
    out=[0]*16
    for c in range(4):
        col=[a[4*c+i] for i in range(4)]
        m=mix_single_column(col)
        for i in range(4):
            out[4*c+i]=m[i]
    return bytes(out)

def add_round_key(s, rk):
    return bytes(x^y for x,y in zip(s,rk))

def rot_word(w):
    return w[1:]+w[:1]

def sub_word(w):
    return bytes(SBOX[b] for b in w)

def key_expansion_128(key, Nr=3):
    assert len(key)==16
    Nk=4
    Nb=4
    words=[bytearray(key[4*i:4*i+4]) for i in range(Nk)]
    total_words=Nb*(Nr+1)
    i=Nk
    while i<total_words:
        temp=bytes(words[i-1])
        if i%Nk==0:
            temp = bytes(x^y for x,y in zip(sub_word(rot_word(temp)), bytes([RCON[i//Nk],0,0,0])))
        new=bytes(x^y for x,y in zip(words[i-Nk], temp))
        words.append(bytearray(new))
        i+=1
    round_keys=[]
    for r in range(Nr+1):
        rk=b''.join(bytes(words[4*r+j]) for j in range(4))
        round_keys.append(rk)
    return round_keys

def aes3_encrypt_block(pt, key):
    rks=key_expansion_128(key, Nr=3)
    s=add_round_key(pt, rks[0])
    for r in range(1,3):
        s=sub_bytes(s)
        s=shift_rows(s)
        s=mix_columns(s)
        s=add_round_key(s, rks[r])
    s=sub_bytes(s)
    s=shift_rows(s)
    s=add_round_key(s, rks[3])
    return s

# Z3 model
bv8=z3.BitVecSort(8)
sbox_arr = z3.K(bv8, z3.BitVecVal(0,8))
for i,v in enumerate(SBOX):
    sbox_arr = z3.Store(sbox_arr, z3.BitVecVal(i,8), z3.BitVecVal(v,8))

def zsub(b):
    return z3.Select(sbox_arr, b)

def zxtime(b):
    return z3.If((b & 0x80) == 0, (b<<1) & 0xff, ((b<<1) & 0xff) ^ 0x1b)

def zmix_col(a0,a1,a2,a3):
    t = a0 ^ a1 ^ a2 ^ a3
    u = a0
    b0 = a0 ^ t ^ zxtime(a0 ^ a1)
    b1 = a1 ^ t ^ zxtime(a1 ^ a2)
    b2 = a2 ^ t ^ zxtime(a2 ^ a3)
    b3 = a3 ^ t ^ zxtime(a3 ^ u)
    return [b0,b1,b2,b3]

def zshift_rows(s):
    a=s
    out=a[:]
    out[1],out[5],out[9],out[13] = a[5],a[9],a[13],a[1]
    out[2],out[6],out[10],out[14] = a[10],a[14],a[2],a[6]
    out[3],out[7],out[11],out[15] = a[15],a[3],a[7],a[11]
    return out

def zmix_columns(s):
    out=s[:]
    for c in range(4):
        i=4*c
        out[i:i+4] = zmix_col(s[i],s[i+1],s[i+2],s[i+3])
    return out

def zkey_expansion_128(key_bytes, Nr=3):
    Nk=4; Nb=4
    words=[key_bytes[4*i:4*i+4] for i in range(Nk)]
    total=Nb*(Nr+1)
    rcon=[0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    def rot_word(w):
        return w[1:]+w[:1]
    def sub_word(w):
        return [zsub(b) for b in w]
    i=Nk
    while i<total:
        temp=words[i-1]
        if i%Nk==0:
            temp=sub_word(rot_word(temp))
            temp=[temp[0]^z3.BitVecVal(rcon[i//Nk],8), temp[1], temp[2], temp[3]]
        new=[words[i-Nk][j]^temp[j] for j in range(4)]
        words.append(new)
        i+=1
    round_keys=[]
    for r in range(Nr+1):
        rk=[]
        for j in range(4):
            rk += words[4*r+j]
        round_keys.append(rk)
    return round_keys

def zaes3_encrypt(pt_bytes, key_bytes):
    rks=zkey_expansion_128(key_bytes, Nr=3)
    s=[pt_bytes[i]^rks[0][i] for i in range(16)]
    for r in range(1,3):
        s=[zsub(b) for b in s]
        s=zshift_rows(s)
        s=zmix_columns(s)
        s=[s[i]^rks[r][i] for i in range(16)]
    s=[zsub(b) for b in s]
    s=zshift_rows(s)
    s=[s[i]^rks[3][i] for i in range(16)]
    return s

# ------------ INJECT DATA ------------
from pathlib import Path
import sys

# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from AES import supreme_encryption
N = 64 # number of plaintext-ciphetext pairs used
SECRET_KEY = "6cebfd76208afcd8a80501071a22c835"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 3, "")
    pairs.append((bytes.fromhex(pt), bytes.fromhex(ct)))
# --------------------------------------

sel=[0,1,2,3]  # 4 pairs
k=[z3.BitVec(f'k{i}',8) for i in range(16)]
solver=z3.Solver()

for idx in sel:
    pt,ct=pairs[idx]
    ptb=[z3.BitVecVal(b,8) for b in pt]
    out=zaes3_encrypt(ptb,k)
    for i,b in enumerate(ct):
        solver.add(out[i]==z3.BitVecVal(b,8))

print('constraints', len(solver.assertions()))
start=time.time();
res=solver.check();
print("TIME", time.time()-start)
print('sat?', res)
if res==z3.sat:
    m=solver.model()
    key=bytes([m.evaluate(k[i], model_completion=True).as_long() for i in range(16)])
    print('key', key.hex())
    # verify on 20 pairs
    ok=0
    for i,(pt,ct) in enumerate(pairs[:20]):
        if aes3_encrypt_block(pt,key)==ct:
            ok+=1
    print('ok first20', ok)