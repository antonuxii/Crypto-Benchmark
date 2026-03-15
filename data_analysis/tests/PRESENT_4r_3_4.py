'''
SAT attempt from the model. Check if it can ever converge when given more time (3h or so). True key: "5be4393b843ae17d7af6"
We ran it on the athena01 machine afterwards and got the following output:

constraints 8
TIME 2287.632527112961
sat? unsat

Failed attempt, independent of sandbox tiemouts.
'''

from z3 import BitVec, BitVecVal, Solver, Extract, Concat, LShR, RotateLeft, If, simplify, sat

import time as time

# -------------- INJECT DATA -------------
import sys
from pathlib import Path
# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))
from PRESENT import supreme_encryption

N = 8 # number of plaintext-ciphetext pairs requested by the model
SECRET_KEY = "5be4393b843ae17d7af6"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 2, "")
    pairs.append((int(pt,16), int(ct,16)))

# ------------------------------------------

SBOX = [0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2]
INV_SBOX = [0]*16
for i,v in enumerate(SBOX):
    INV_SBOX[v]=i

# bit permutation P(i) for PRESENT
P = [0]*64
for i in range(63):
    P[i] = (16*i) % 63
P[63] = 63
INV_P = [0]*64
for i,p in enumerate(P):
    INV_P[p] = i


def sbox4_bv(x4):
    # x4: 4-bit BitVec
    assert x4.size()==4
    # chain Ifs
    r = BitVecVal(0,4)
    for i,val in enumerate(SBOX):
        r = If(x4 == BitVecVal(i,4), BitVecVal(val,4), r)
    return r

def sbox_layer64_bv(x64):
    # apply sbox nibblewise, nibble0 is least significant
    out_nibs=[]
    for n in range(16):
        nib = Extract(4*n+3, 4*n, x64)
        out_nibs.append(sbox4_bv(nib))
    # rebuild 64-bit
    y = out_nibs[15]
    for n in range(14,-1,-1):
        y = Concat(y, out_nibs[n])
    return y

def p_layer64_bv(x64):
    # bit permutation: output bit P[i] = input bit i
    bits = [Extract(i,i,x64) for i in range(64)]
    outbits=[None]*64
    for i in range(64):
        outbits[P[i]] = bits[i]
    # concat msb..lsb
    y = outbits[63]
    for i in range(62,-1,-1):
        y = Concat(y, outbits[i])
    return y

def present80_roundkeys_bv(K80, rounds=4):
    k = K80
    rks=[]
    for r in range(1, rounds+2):
        rks.append(Extract(79,16,k))
        if r==rounds+1:
            break
        # update
        k = RotateLeft(k, 61)
        top = Extract(79,76,k)
        top_s = sbox4_bv(top)
        k = Concat(top_s, Extract(75,0,k))
        k = k ^ (BitVecVal(r,80) << 15)
    return rks

def present80_encrypt4_bv(K80, pt64, rounds=4):
    rks = present80_roundkeys_bv(K80, rounds)
    s = pt64
    for r in range(rounds):
        s = s ^ rks[r]
        s = sbox_layer64_bv(s)
        s = p_layer64_bv(s)
    s = s ^ rks[rounds]
    return s

# Quick test vector check using python implementation later, but here check bv model vs python for known key

def present80_encrypt4_py(key80, pt64, rounds=4):
    # key schedule
    mask80=(1<<80)-1
    k=key80 & mask80
    rks=[]
    for r in range(1, rounds+2):
        rks.append((k>>16) & ((1<<64)-1))
        if r==rounds+1:
            break
        k = ((k<<61) | (k>>(80-61))) & mask80
        ms = (k>>76) & 0xF
        k = ((SBOX[ms]<<76) | (k & ((1<<76)-1)))
        k ^= (r & 0x1F) << 15
    # rounds
    s=pt64 & ((1<<64)-1)
    for r in range(rounds):
        s ^= rks[r]
        # sbox layer
        y=0
        for n in range(16):
            nib=(s>>(4*n)) & 0xF
            y |= SBOX[nib] << (4*n)
        s=y
        # pLayer
        y=0
        for i in range(64):
            bit=(s>>i)&1
            y |= bit<<P[i]
        s=y
    s ^= rks[rounds]
    return s

# now solve for oracle key

st = time.time()
K=BitVec('K',80)
sol=Solver()
for pt,ct in pairs:
    sol.add(present80_encrypt4_bv(K, BitVecVal(pt,64)) == BitVecVal(ct,64))
print('constraints', len(pairs))
res=sol.check()
et = time.time()
print("TIME", et-st)
print('sat?',res)
if res==sat:
    m=sol.model()
    kval=m[K].as_long()
    print('recovered key:', hex(kval))
    # verify on all pairs
    ok=0
    for pt,ct in pairs:
        if present80_encrypt4_py(kval,pt)==ct:
            ok += 1
    print('verified', ok, '/', len(pairs))