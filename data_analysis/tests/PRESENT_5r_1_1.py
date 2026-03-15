'''
SAT approach from the model. Run independently and stopped manually. Last output was:

loaded 12 pairs
constraints 3
solving...
^Csat? unknown
time 10941.206865787506

Conclusion: Sample fails, regardless of sandbox timeouts
'''

from z3 import *
import time as time

# ------------- INJECT DATA ------------
from pathlib import Path
import sys
# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))
from PRESENT import supreme_encryption

N = 12 # number of plaintext-ciphetext pairs used
SECRET_KEY = "5be4393b843ae17d7af6"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 2, "")
    pairs.append((int(pt,16), int(ct,16)))
print('loaded',len(pairs),'pairs')

# -----------------------------------------

SBOX=[0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]

# build sbox as constant array mapping 4-bit->4-bit
BV4=BitVecSort(4)
arr = K(BV4, BitVecVal(0,4))
for i,v in enumerate(SBOX):
    arr = Store(arr, BitVecVal(i,4), BitVecVal(v,4))

def sbox4(x):
    return Select(arr, x)

# permutation
P=[0]*64
for i in range(63):
    P[i]=(i*16)%63
P[63]=63

# pLayer on 64-bit bitvec

def pLayer_bv(x):
    out = BitVecVal(0,64)
    for i in range(64):
        bit = Extract(i,i,x)
        out = out | (ZeroExt(63,bit) << P[i])
    return out


def sboxLayer_bv(x):
    out = BitVecVal(0,64)
    for i in range(16):
        nib = Extract(4*i+3,4*i,x)
        out = out | (ZeroExt(60, sbox4(nib)) << (4*i))
    return out


def roundkeys_80_bv(master, rounds=5):
    # returns list rks[0..rounds] where rks[i]=roundkey[i+1]
    k = master
    rks=[]
    for r in range(1, rounds+2):
        rks.append(Extract(79,16,k))
        if r==rounds+1:
            break
        k = RotateLeft(k, 61)
        ms = Extract(79,76,k)
        k = Concat(sbox4(ms), Extract(75,0,k))
        k = k ^ (BitVecVal(r,80) << 15)
    return rks


def present5_bv(pt, master):
    rks = roundkeys_80_bv(master, rounds=5)
    st = pt
    for r in range(5):
        st = st ^ rks[r]
        st = sboxLayer_bv(st)
        st = pLayer_bv(st)
    st = st ^ rks[5]
    return st

# Solve for key using first few pairs
k = BitVec('k',80)
solver = Solver()
use=3
for i in range(use):
    pt,ct = pairs[i]
    solver.add(present5_bv(BitVecVal(pt,64), k) == BitVecVal(ct,64))
print('constraints',use)

st = time.time()

print('solving...')
res=solver.check()

et = time.time()
print('sat?',res)
print("time", et-st)
if res==sat:
    m=solver.model()
    kv=m[k].as_long()
    print('key',hex(kv))

    # verify against more pairs with Python implementation
    # python present
    def rotl(x,r,bits):
        r%=bits
        return ((x<<r)&((1<<bits)-1)) | (x>>(bits-r))
    # pLayer LUT
    def pLayer_int(state):
        out=0
        for i in range(64):
            out |= ((state>>i)&1) << P[i]
        return out
    def sboxLayer_int(state):
        out=0
        for i in range(16):
            out |= SBOX[(state>>(4*i))&0xF] << (4*i)
        return out
    def gen_rks(master_key, rounds=5):
        reg=master_key & ((1<<80)-1)
        rks=[]
        for r in range(1,rounds+2):
            rks.append((reg>>16)&((1<<64)-1))
            if r==rounds+1: break
            reg=rotl(reg,61,80)
            ms=(reg>>76)&0xF
            reg=(reg & ((1<<76)-1)) | (SBOX[ms]<<76)
            reg ^= (r & 0x1F) << 15
        return rks
    def enc5(pt, key):
        rks=gen_rks(key,5)
        st=pt
        for r in range(5):
            st ^= rks[r]
            st = sboxLayer_int(st)
            st = pLayer_int(st)
        st ^= rks[5]
        return st & ((1<<64)-1)

    ok=0
    for pt,ct in pairs[:10]:
        if enc5(pt, kv)==ct:
            ok+=1
    print('verified on',ok,'/10 pairs')