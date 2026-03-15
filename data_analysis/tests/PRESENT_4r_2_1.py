'''
SAT attempt from the model. Check if it can ever converge when given more time (3h or so). True key: "5be4393b843ae17d7af6"
We ran it on the athena01 machine afterwards and got the following output:

check sat
TIME 130.57138442993164
key 0x5be4393b843ae17d7af6
all pairs verify True

so the sample was actually succesful, just not within the sandbox time constraints imposed.
'''

from z3 import *
import time


# -------------- INJECT DATA -----------

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
print('Using N',N)

# -------------------------

# Reuse functions from previous cell by redefining minimally
SBOX = [0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]
P = [0]*64
for i in range(63): P[i]=(16*i)%63
P[63]=63

def sbox4_bv(x4):
    expr = BitVecVal(SBOX[0],4)
    for i in range(1,16):
        expr = If(x4 == BitVecVal(i,4), BitVecVal(SBOX[i],4), expr)
    return expr

def sboxlayer_bv(x64):
    res = BitVecVal(0,64)
    for j in range(16):
        nib = Extract(4*j+3,4*j,x64)
        sb = sbox4_bv(nib)
        res = res | (ZeroExt(60,sb) << (4*j))
    return res

def player_bv(x64):
    res = BitVecVal(0,64)
    for i in range(64):
        bit = Extract(i,i,x64)
        res = res | (ZeroExt(63, bit) << P[i])
    return res

def key_schedule_roundkeys_bv(master80, rounds=4):
    k = master80
    rks=[]
    for r in range(1, rounds+2):
        rks.append( Extract(79,16,k) )
        if r == rounds+1:
            break
        low19 = Extract(18,0,k)
        high61 = Extract(79,19,k)
        k = Concat(low19, high61)
        top = Extract(79,76,k)
        k = Concat(sbox4_bv(top), Extract(75,0,k))
        k = k ^ (ZeroExt(75, BitVecVal(r,5)) << 15)
    return rks

def present4_encrypt_bv_with_rks(pt64, rks):
    state = pt64
    for r in range(4):
        state = state ^ rks[r]
        state = sboxlayer_bv(state)
        state = player_bv(state)
    state = state ^ rks[4]
    return state

key = BitVec('key',80)
rks = key_schedule_roundkeys_bv(key, rounds=4)

s = Solver()
# Add constraints for all pairs
for (pt,ct) in pairs:
    ptbv = BitVecVal(pt,64)
    ctbv = BitVecVal(ct,64)
    s.add(present4_encrypt_bv_with_rks(ptbv,rks) == ctbv)

start=time.time()
res = s.check()
elapsed=time.time()-start
print('check', res)
print("TIME", elapsed)
if res==sat:
    m=s.model()
    kval=m[key].as_long()
    print('key', hex(kval))
    # verify with concrete encryption on all pairs
    def present4_encrypt_int(pt, master):
        # key schedule int
        SBOX = [0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]
        P=[0]*64
        for i in range(63): P[i]=(16*i)%63
        P[63]=63
        def sboxlayer_int(x):
            y=0
            for j in range(16):
                y |= SBOX[(x>>(4*j))&0xF] << (4*j)
            return y
        def player_int(x):
            y=0
            for i in range(64):
                y |= ((x>>i)&1) << P[i]
            return y
        def roundkeys_int(master, rounds=4):
            k=master
            rks=[]
            for r in range(1, rounds+2):
                rks.append((k>>16)&((1<<64)-1))
                if r==rounds+1: break
                k = ((k & ((1<<19)-1))<<61) | (k>>19)
                top=(k>>76)&0xF
                k = (k & ((1<<76)-1)) | (SBOX[top]<<76)
                k ^= (r & 0x1F) << 15
            return rks
        s=pt
        rks=roundkeys_int(master, rounds=4)
        for r in range(4):
            s ^= rks[r]
            s = sboxlayer_int(s)
            s = player_int(s)
        s ^= rks[4]
        return s
    ok=True
    for i,(pt,ct) in enumerate(pairs):
        if present4_encrypt_int(pt,kval)!=ct:
            print('mismatch at', i)
            ok=False
            break
    print('all pairs verify', ok)