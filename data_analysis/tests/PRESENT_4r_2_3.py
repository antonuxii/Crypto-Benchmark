'''
SAT attempt from the model. Check if it can ever converge when given more time (3h or so). I generated a file present4.txt with 12 pairs and key "5be4393b843ae17d7af6"
We ran it on the athena01 machine afterwards and got the following output:

testvector ok? 0xff172a02d9c1278f True
loaded pairs 12
first pair 0x7a874cc592e923fe 0xb666b5e209f2dc36
solving with 12 pairs...
TIME 181.11143732070923
z3 status: sat
recovered key: 0x5be4393b843ae17d7af6
check 0x7a874cc592e923fe 0xb666b5e209f2dc36 -> 0xb666b5e209f2dc36 OK
check 0x80387f8cc89ce1c 0x7f08950bc34ce349 -> 0x7f08950bc34ce349 OK
check 0x77c3c04922e8d20 0x5d63c02d2b38af22 -> 0x5d63c02d2b38af22 OK
verified 3 /3

That is, the attack is succesful, just not within the sandbox constraints.
'''


from pathlib import Path
import time as time

SBOX=[0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2]

def present_sbox(n):
    return SBOX[n]

def sbox_layer(x):
    y=0
    for i in range(16):
        y |= present_sbox((x>>(4*i))&0xF) << (4*i)
    return y

def p_layer(x):
    y=0
    for i in range(63):
        y |= ((x>>i)&1) << ((16*i)%63)
    y |= ((x>>63)&1) << 63
    return y

def key_schedule_80(master_key, rounds_needed=5):
    key=master_key & ((1<<80)-1)
    rks=[]
    for r in range(1, rounds_needed+1):
        rks.append((key >> 16) & ((1<<64)-1))
        key = ((key<<61) & ((1<<80)-1)) | (key>>(19))
        top = (key>>76)&0xF
        key = (key & ((1<<76)-1)) | (present_sbox(top)<<76)
        key ^= (r & 0x1F) << 15
    return rks

def present_encrypt_4r(pt, master_key):
    rks=key_schedule_80(master_key,5)
    s=pt & ((1<<64)-1)
    for r in range(4):
        s ^= rks[r]
        s = sbox_layer(s)
        s = p_layer(s)
    s ^= rks[4]
    return s

# Verify test vector
key=int('0123456789abcdef0123',16)
pt=int('1111111111111111',16)
ct=present_encrypt_4r(pt,key)
print('testvector ok?', hex(ct), ct==int('ff172a02d9c1278f',16))

# Load oracle pairs
pairs=[]
for line in Path('present4.txt').read_text().strip().splitlines():
    a,b=line.strip().split(',')
    pairs.append((int(a,16), int(b,16)))
print('loaded pairs', len(pairs))
print('first pair', hex(pairs[0][0]), hex(pairs[0][1]))

# Try Z3
import z3

def z3_sbox4(x4):
    # x4 is 4-bit BitVec
    expr = None
    for i,v in enumerate(SBOX):
        cond = (x4 == z3.BitVecVal(i,4))
        val  = z3.BitVecVal(v,4)
        expr = val if expr is None else z3.If(cond, val, expr)
    return expr

def z3_sbox_layer(x64):
    # apply to each nibble (LSB nibble is bits 3..0)
    out = z3.BitVecVal(0,64)
    for i in range(16):
        nib = z3.Extract(4*i+3, 4*i, x64)
        out = out | z3.ZeroExt(60, z3_sbox4(nib)) << (4*i)
    return out

def z3_p_layer(x64):
    out = z3.BitVecVal(0,64)
    for i in range(63):
        bit = z3.Extract(i,i,x64)  # 1-bit BV
        out = z3.Concat(z3.BitVecVal(0,63), bit)  # place in LSB then shift
        # Actually easier: make 64-bit by ZeroExt
    
# build p_layer properly

def z3_bit_to_64(b1):
    return z3.ZeroExt(63, b1)

def z3_p_layer(x64):
    out = z3.BitVecVal(0,64)
    for i in range(63):
        bit = z3.Extract(i,i,x64)
        out = out | (z3_bit_to_64(bit) << ((16*i)%63))
    bit63 = z3.Extract(63,63,x64)
    out = out | (z3_bit_to_64(bit63) << 63)
    return out

def z3_key_schedule_80(k80, rounds_needed=5):
    key=k80
    rks=[]
    mask80=z3.BitVecVal((1<<80)-1,80)
    for r in range(1, rounds_needed+1):
        rks.append(z3.Extract(79,16,key))
        key = z3.RotateLeft(key,61)
        top = z3.Extract(79,76,key)
        top2 = z3_sbox4(top)
        key = z3.Concat(top2, z3.Extract(75,0,key))
        key = key ^ (z3.ZeroExt(75, z3.BitVecVal(r & 0x1F,5)) << 15)
        key = key & mask80
    return rks

def z3_encrypt_4r(pt64, k80):
    rks=z3_key_schedule_80(k80,5)
    s = pt64
    for r in range(4):
        s = s ^ rks[r]
        s = z3_sbox_layer(s)
        s = z3_p_layer(s)
    s = s ^ rks[4]
    return s

# create solver
k = z3.BitVec('k',80)
solver = z3.Solver()

# Use first 8-12 pairs to constrain
useN=min(12,len(pairs))
for i,(pt_i,ct_i) in enumerate(pairs[:useN]):
    pt_bv=z3.BitVecVal(pt_i,64)
    ct_bv=z3.BitVecVal(ct_i,64)
    solver.add(z3_encrypt_4r(pt_bv,k) == ct_bv)

st = time.time()
print('solving with', useN, 'pairs...')
res=solver.check()
et = time.time()
print("TIME", et-st)
print('z3 status:', res)
if res==z3.sat:
    m=solver.model()
    key_val=m[k].as_long()
    print('recovered key:', hex(key_val))
    # verify on 3 pairs
    ok=0
    for pt_i,ct_i in pairs[:3]:
        c=present_encrypt_4r(pt_i,key_val)
        if c==ct_i:
            ok+=1
        print('check', hex(pt_i), hex(ct_i), '->', hex(c), 'OK' if c==ct_i else 'FAIL')
    print('verified', ok, '/3')
else:
    print('unsat/unknown')