'''
Sample suffered sandbox timeouts. We run its code independently to test whether the sandbox timeout constraints were too tight.
We obtain the following output:
CNF vars 6912 clauses 214784
TIME 66.36779475212097
sat? True
rk0 1e7bf3703402aa33da1c4382b367b039
rk1 ae7d2127a0fa37ebbf61c24507f94d50
rk2 92568c071b965412c0224c5eddec15df
rk3 c2f7111d4ac93dccff060065ff8792a1
0 True
1 True
2 False
TOTAL TIME: 66.37247943878174
'''

from pysat.formula import CNF, IDPool
from pysat.solvers import Solver
import time

from pathlib import Path
import sys

# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from AES import supreme_encryption
N = 2000 # number of plaintext-ciphetext pairs used
SECRET_KEY = "6cebfd76208afcd8a80501071a22c835"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 3, "")
    pairs.append((bytes.fromhex(pt), bytes.fromhex(ct)))


start = time.time()
Sbox=[
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

# SAT builder
vpool=IDPool(); cnf=CNF(); fresh_counter=0

def fresh(tag='t'):
    global fresh_counter
    fresh_counter += 1
    return vpool.id(f'{tag}_{fresh_counter}')

def var(name):
    return vpool.id(name)

def bits_of_const(byte):
    return [(byte>>i)&1 for i in range(8)]

def add_unit(v,val):
    cnf.append([v] if val else [-v])

def add_xor2(out,a,b):
    cnf.append([-a,-b,-out]); cnf.append([-a,b,out]); cnf.append([a,-b,out]); cnf.append([a,b,-out])

def add_xorN(out,ins):
    if len(ins)==1:
        a=ins[0]; cnf.append([-out,a]); cnf.append([out,-a]); return
    cur=ins[0]
    for j in range(1,len(ins)):
        tmp=fresh('xor')
        add_xor2(tmp, cur, ins[j])
        cur=tmp
    cnf.append([-out,cur]); cnf.append([out,-cur])

def add_sbox(xbits,ybits):
    for i in range(256):
        out=Sbox[i]
        mism=[-xbits[k] if ((i>>k)&1) else xbits[k] for k in range(8)]
        for k in range(8):
            lit = ybits[k] if ((out>>k)&1) else -ybits[k]
            cnf.append(mism+[lit])

def shift_rows_bytes(state):
    s=state[:]
    s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1]
    s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]
    return s

def mul2_bits(x):
    return [x[7], ('xor',[x[0],x[7]]), x[1], ('xor',[x[2],x[7]]), ('xor',[x[3],x[7]]), x[4], x[5], x[6]]

def mul3_bits(x):
    m2=mul2_bits(x)
    return [('xor',[m2[i],x[i]]) for i in range(8)]

def realize(e):
    if isinstance(e,int):
        return e
    ins=[realize(x) for x in e[1]]
    out=fresh('lin')
    add_xorN(out, ins)
    return out

def mix_columns(state, prefix):
    out=[[var(f'{prefix}_mc_{bi}_{k}') for k in range(8)] for bi in range(16)]
    for c in range(4):
        a0,a1,a2,a3=state[4*c:4*c+4]
        b0=[('xor',[mul2_bits(a0)[k], mul3_bits(a1)[k], a2[k], a3[k]]) for k in range(8)]
        b1=[('xor',[a0[k], mul2_bits(a1)[k], mul3_bits(a2)[k], a3[k]]) for k in range(8)]
        b2=[('xor',[a0[k], a1[k], mul2_bits(a2)[k], mul3_bits(a3)[k]]) for k in range(8)]
        b3=[('xor',[mul3_bits(a0)[k], a1[k], a2[k], mul2_bits(a3)[k]]) for k in range(8)]
        bs=[b0,b1,b2,b3]
        for r in range(4):
            for k in range(8):
                rhs=realize(bs[r][k])
                ob=out[4*c+r][k]
                cnf.append([-ob,rhs]); cnf.append([ob,-rhs])
    return out

def add_round_key(state, rk, prefix):
    out=[[var(f'{prefix}_ark_{bi}_{k}') for k in range(8)] for bi in range(16)]
    for bi in range(16):
        for k in range(8):
            add_xor2(out[bi][k], state[bi][k], rk[bi][k])
    return out

def sub_bytes(state,prefix):
    out=[[var(f'{prefix}_sb_{bi}_{k}') for k in range(8)] for bi in range(16)]
    for bi in range(16):
        add_sbox(state[bi], out[bi])
    return out

# round key vars shared
round_keys=[]
for r in range(4):
    rk=[]
    for bi in range(16):
        rk.append([var(f'rk{r}_{bi}_{k}') for k in range(8)])
    round_keys.append(rk)

use_n=2
for pi,(pt,ct) in enumerate(pairs[:use_n]):
    st=[[var(f'p{pi}_pt_{bi}_{k}') for k in range(8)] for bi in range(16)]
    for bi in range(16):
        for k,val in enumerate(bits_of_const(pt[bi])):
            add_unit(st[bi][k], val)
    st=add_round_key(st, round_keys[0], f'p{pi}_r0')
    st=sub_bytes(st,f'p{pi}_r1'); st=shift_rows_bytes(st); st=mix_columns(st,f'p{pi}_r1'); st=add_round_key(st,round_keys[1],f'p{pi}_r1')
    st=sub_bytes(st,f'p{pi}_r2'); st=shift_rows_bytes(st); st=mix_columns(st,f'p{pi}_r2'); st=add_round_key(st,round_keys[2],f'p{pi}_r2')
    st=sub_bytes(st,f'p{pi}_r3'); st=shift_rows_bytes(st); st=add_round_key(st,round_keys[3],f'p{pi}_r3')
    for bi in range(16):
        for k,val in enumerate(bits_of_const(ct[bi])):
            add_unit(st[bi][k], val)

print('CNF vars',vpool.top,'clauses',len(cnf.clauses))
start=time.time()
with Solver(name='cadical153', bootstrap_with=cnf) as s:
    sat=s.solve()
    print("TIME", time.time()-start)
    print('sat?',sat)
    model=set(s.get_model())

# decode round keys
rk_bytes=[]
for r in range(4):
    rb=bytearray(16)
    for bi in range(16):
        val=0
        for k in range(8):
            if round_keys[r][bi][k] in model:
                val |= (1<<k)
        rb[bi]=val
    rk_bytes.append(bytes(rb))

print('rk0',rk_bytes[0].hex())
print('rk1',rk_bytes[1].hex())
print('rk2',rk_bytes[2].hex())
print('rk3',rk_bytes[3].hex())

# Concrete AES3 encryption using recovered round keys

def aes3_encrypt_with_rks(pt, rks):
    def sub_bytes(st):
        return [Sbox[b] for b in st]
    def shift_rows(st):
        st=st[:]
        st[1],st[5],st[9],st[13]=st[5],st[9],st[13],st[1]
        st[2],st[6],st[10],st[14]=st[10],st[14],st[2],st[6]
        st[3],st[7],st[11],st[15]=st[15],st[3],st[7],st[11]
        return st
    def xtime(a):
        return ((a<<1)&0xff) ^ (0x1b if a&0x80 else 0)
    def mul(a,b):
        res=0
        for _ in range(8):
            if b&1: res^=a
            a=xtime(a); b>>=1
        return res
    def mix_columns(st):
        st=st[:]
        for c in range(4):
            i=4*c
            a0,a1,a2,a3=st[i:i+4]
            st[i+0]=mul(a0,2)^mul(a1,3)^a2^a3
            st[i+1]=a0^mul(a1,2)^mul(a2,3)^a3
            st[i+2]=a0^a1^mul(a2,2)^mul(a3,3)
            st[i+3]=mul(a0,3)^a1^a2^mul(a3,2)
        return st
    def ark(st,rk):
        return [st[i]^rk[i] for i in range(16)]

    st=list(pt)
    st=ark(st,list(rks[0]))
    for r in [1,2]:
        st=sub_bytes(st); st=shift_rows(st); st=mix_columns(st); st=ark(st,list(rks[r]))
    st=sub_bytes(st); st=shift_rows(st); st=ark(st,list(rks[3]))
    return bytes(st)

# Verify at least 3 pairs
for i in range(3):
    pt,ct=pairs[i]
    c=aes3_encrypt_with_rks(pt,rk_bytes)
    print(i, c.hex()==ct.hex())

et = time.time()
print(f"TOTAL TIME: {et-start}")