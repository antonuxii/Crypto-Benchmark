from pathlib import Path

def hex_to_int(h):
    return int(h,16)

def int_to_hex(x, nbytes=8):
    return f"{x:0{2*nbytes}x}"

# DES tables (standard)
IP = [
58,50,42,34,26,18,10,2,
60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6,
64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1,
59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,
63,55,47,39,31,23,15,7
]
FP = [
40,8,48,16,56,24,64,32,
39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,
35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,
33,1,41,9,49,17,57,25
]
E = [
32,1,2,3,4,5,
4,5,6,7,8,9,
8,9,10,11,12,13,
12,13,14,15,16,17,
16,17,18,19,20,21,
20,21,22,23,24,25,
24,25,26,27,28,29,
28,29,30,31,32,1
]
P = [
16,7,20,21,
29,12,28,17,
1,15,23,26,
5,18,31,10,
2,8,24,14,
32,27,3,9,
19,13,30,6,
22,11,4,25
]
# S-boxes, indexed [box][input 0..63] -> output 0..15
S = [
# S1
[
14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
],
# S2
[
15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
],
# S3
[
10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
],
# S4
[
7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
],
# S5
[
2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
],
# S6
[
12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
],
# S7
[
4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
],
# S8
[
13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
]
]

PC1 = [
57,49,41,33,25,17,9,
1,58,50,42,34,26,18,
10,2,59,51,43,35,27,
19,11,3,60,52,44,36,
63,55,47,39,31,23,15,
7,62,54,46,38,30,22,
14,6,61,53,45,37,29,
21,13,5,28,20,12,4
]
PC2 = [
14,17,11,24,1,5,
3,28,15,6,21,10,
23,19,12,4,26,8,
16,7,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32
]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


def permute(x, table, inbits):
    out = 0
    for pos in table:
        out = (out<<1) | ((x >> (inbits - pos)) & 1)
    return out

def left_rotate28(x, s):
    x &= (1<<28)-1
    return ((x<<s) | (x>>(28-s))) & ((1<<28)-1)

def des_k1_from_key64(key64):
    k56 = permute(key64, PC1, 64)
    C0 = (k56 >> 28) & ((1<<28)-1)
    D0 = k56 & ((1<<28)-1)
    C1 = left_rotate28(C0, SHIFTS[0])
    D1 = left_rotate28(D0, SHIFTS[0])
    CD1 = (C1<<28) | D1
    k1 = permute(CD1, PC2, 56)
    return k1

def sbox_substitution(x48):
    # x48: 48-bit
    out32 = 0
    for i in range(8):
        chunk = (x48 >> (42-6*i)) & 0x3f
        row = ((chunk & 0x20)>>4) | (chunk & 0x01)
        col = (chunk >> 1) & 0x0f
        out4 = S[i][row*16 + col]
        out32 = (out32<<4) | out4
    return out32

def f_func(R32, k48):
    er = permute(R32, E, 32)
    x = er ^ k48
    s_out = sbox_substitution(x)
    return permute(s_out, P, 32)

def des1_encrypt_block(pt64, k48):
    ip = permute(pt64, IP, 64)
    L0 = (ip>>32)&0xffffffff
    R0 = ip & 0xffffffff
    L1 = R0
    R1 = L0 ^ f_func(R0, k48)
    preout = (R1<<32) | L1  # final swap
    ct = permute(preout, FP, 64)
    return ct

# verify given test vector
key = 0x0123456789abcdef
pt = 0x1111111111111111
k1 = des_k1_from_key64(key)
ct = des1_encrypt_block(pt, k1)
print('k1 =', f"{k1:012x}")
print('ct =', f"{ct:016x}")
assert ct == 0x5041505004500514

# Build P inverse
P_INV = [0]*32
for i,p in enumerate(P, start=1):
    P_INV[p-1] = i

# Attack using oracle outputs

from pathlib import Path
import sys

# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from DES import supreme_encryption
N = 4 # number of plaintext-ciphetext pairs used
SECRET_KEY = "58ca708933418d30f281"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 1, "")
    pairs.append((hex_to_int(pt), hex_to_int(ct)))

# Precompute reverse mapping for each S-box: output nibble -> list of 6-bit inputs
preimages = [[[] for _ in range(16)] for __ in range(8)]
for bi in range(8):
    for x in range(64):
        row = ((x & 0x20)>>4) | (x & 0x01)
        col = (x >> 1) & 0x0f
        y = S[bi][row*16+col]
        preimages[bi][y].append(x)

cand = [set(range(64)) for _ in range(8)]

bad_pairs=0
for (pt64, ct64) in pairs:
    ip_pt = permute(pt64, IP, 64)
    L0 = (ip_pt>>32)&0xffffffff
    R0 = ip_pt & 0xffffffff
    ip_ct = permute(ct64, IP, 64)
    R1 = (ip_ct>>32)&0xffffffff
    L1 = ip_ct & 0xffffffff
    if L1 != R0:
        bad_pairs += 1
        continue
    f_out = L0 ^ R1
    s_out = permute(f_out, P_INV, 32)
    ER = permute(R0, E, 32)
    for i in range(8):
        out4 = (s_out >> (28-4*i)) & 0xf
        er6 = (ER >> (42-6*i)) & 0x3f
        poss = {er6 ^ x for x in preimages[i][out4]}
        cand[i].intersection_update(poss)

print('bad_pairs:', bad_pairs)
print('candidate sizes per sbox:', [len(s) for s in cand])

# if unique, assemble k1
if all(len(s)==1 for s in cand):
    k1_rec = 0
    for i in range(8):
        k1_rec = (k1_rec<<6) | next(iter(cand[i]))
    print('recovered k1:', f"{k1_rec:012x}")
else:
    print('Not unique yet')
    k1_rec=None

# verify on first 3 pairs
if k1_rec is not None:
    for j in range(3):
        pt64, ct64 = pairs[j]
        ccalc = des1_encrypt_block(pt64, k1_rec)
        print(j, int_to_hex(pt64), int_to_hex(ct64), int_to_hex(ccalc), 'OK' if ccalc==ct64 else 'FAIL')

# verify on all pairs quickly
if k1_rec is not None:
    ok = sum(des1_encrypt_block(pt, k1_rec)==ct for pt,ct in pairs)
    print('matches:', ok, '/', len(pairs))