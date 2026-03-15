# Linear Attack. Stored because I wanted to analyse why it fails to recover the key?

from pathlib import Path
import math

# --- constants / helpers ---
SBOX = [0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]
INV_SBOX=[0]*16
for i,v in enumerate(SBOX):
    INV_SBOX[v]=i
MASK80=(1<<80)-1

P=[0]*64
for i in range(63):
    P[i]=(16*i)%63
P[63]=63
Pinv=[0]*64
for i,p in enumerate(P):
    Pinv[p]=i

def mask_inv_p(mask:int)->int:
    out=0
    while mask:
        lsb=mask & -mask
        i=lsb.bit_length()-1
        out |= 1<<Pinv[i]
        mask ^= lsb
    return out

# trail search options
opts_by_b=[[] for _ in range(16)]
for b in range(16):
    for a in range(16):
        s=0
        for x in range(16):
            s += 1 if (((a & x).bit_count() ^ (b & SBOX[x]).bit_count()) & 1)==0 else -1
        if s==0: continue
        logc=math.log2(abs(s))-4.0
        sign=1 if s>0 else -1
        opts_by_b[b].append((a,logc,sign))
    opts_by_b[b].sort(key=lambda t: t[1], reverse=True)

def best_trail_4round(gamma:int, beam=700, per_nibble_keep=200, top_per_nibble=4):
    cand=[(gamma,0.0,1)]
    for _ in range(4):
        tmp=[(mask_inv_p(m),logc,sgn) for (m,logc,sgn) in cand]
        expanded=[]
        for m,logc,sgn in tmp:
            partial=[(0,logc,sgn)]
            for i in range(16):
                b=(m>>(4*i))&0xF
                if b==0: continue
                options=opts_by_b[b][:top_per_nibble]
                shift=4*i
                nxt=[]
                for pm,pl,ps in partial:
                    base=pm
                    for a,lc,ss in options:
                        nxt.append((base | (a<<shift), pl+lc, ps*ss))
                nxt.sort(key=lambda t: t[1], reverse=True)
                partial=nxt[:per_nibble_keep]
            expanded.extend(partial)
        expanded.sort(key=lambda t: t[1], reverse=True)
        cand=expanded[:beam]
    return max(cand, key=lambda t: t[1])

# fast encryption for brute
S8=[0]*256
for x in range(256):
    S8[x]=SBOX[x&0xF] | (SBOX[(x>>4)&0xF]<<4)
P8=[[0]*256 for _ in range(8)]
for byte_pos in range(8):
    for x in range(256):
        out=0
        for bit in range(8):
            if (x>>bit)&1:
                i=8*byte_pos+bit
                out |= 1<<P[i]
        P8[byte_pos][x]=out

def sLayer_fast(s:int)->int:
    out=0
    for i in range(8):
        out |= S8[(s>>(8*i))&0xFF] << (8*i)
    return out

def pLayer_fast(s:int)->int:
    out=0
    for i in range(8):
        out ^= P8[i][(s>>(8*i))&0xFF]
    return out

def enc5_with_rks(pt:int, rks):
    s=pt
    for r in range(5):
        s ^= rks[r]
        s = sLayer_fast(s)
        s = pLayer_fast(s)
    return s ^ rks[5]

def inv_update(keyreg:int, rc:int)->int:
    keyreg ^= (rc & 0x1F) << 15
    ms=(keyreg>>76)&0xF
    keyreg = (keyreg & ((1<<76)-1)) | (INV_SBOX[ms]<<76)
    keyreg = ((keyreg<<19)&MASK80) | (keyreg>>(80-19))
    return keyreg

# approximations
B_list=[1,2,4,8]
R=len(B_list)
alpha=[[0]*16 for _ in range(R)]
for r,b in enumerate(B_list):
    for j in range(16):
        gamma=b<<(4*j)
        a,logc,sgn=best_trail_4round(gamma)
        alpha[r][j]=a

ct_pos=[[P[4*j+bit] for bit in range(4)] for j in range(16)]

# count on full file
counts=[ [ [ [0]*16 for _ in range(2) ] for __ in range(16) ] for ___ in range(R) ]
path=Path('oracle_outputs.txt')
with path.open('r') as f:
    for line in f:
        pt=int(line[0:16],16); ct=int(line[17:33],16)
        for j in range(16):
            p0,p1,p2,p3=ct_pos[j]
            c4=((ct>>p0)&1) | (((ct>>p1)&1)<<1) | (((ct>>p2)&1)<<2) | (((ct>>p3)&1)<<3)
            for r in range(R):
                p=(pt & alpha[r][j]).bit_count() & 1
                counts[r][j][p][c4]+=1

parity4=lambda x: x.bit_count()&1
K6=0
for j in range(16):
    diffs=[ [counts[r][j][0][c]-counts[r][j][1][c] for c in range(16)] for r in range(R) ]
    bestk=0; bestmet=-1
    for k in range(16):
        met=0
        for r,b in enumerate(B_list):
            diff=diffs[r]
            sc=0
            for c in range(16):
                y=INV_SBOX[c^k]
                t=parity4(b & y)
                sc += diff[c] if t==0 else -diff[c]
            met += sc*sc
        if met>bestmet:
            bestmet=met; bestk=k
    for bit in range(4):
        if (bestk>>bit)&1:
            K6 |= 1<<ct_pos[j][bit]
print('K6 candidate:',hex(K6))

# verify by brute-forcing low16 using 3 pairs
pairs=[]
with path.open('r') as f:
    for _ in range(3):
        line=next(f)
        pairs.append((int(line[0:16],16), int(line[17:33],16)))
pt0,ct0=pairs[0]

found=None
for low16 in range(1<<16):
    keyreg5=(K6<<16)|low16
    regs=[0]*6
    regs[5]=keyreg5
    keyreg=keyreg5
    for rc in [5,4,3,2,1]:
        keyreg=inv_update(keyreg,rc)
        regs[rc-1]=keyreg
    rks=[ (regs[r]>>16) & ((1<<64)-1) for r in range(6) ]
    if enc5_with_rks(pt0,rks)!=ct0:
        continue
    ok=True
    for pt,ct in pairs[1:]:
        if enc5_with_rks(pt,rks)!=ct:
            ok=False; break
    if ok:
        found=(regs[0],low16,rks)
        break

print('Found master?', found is not None)
if found:
    master,low16,rks=found
    print('Master key:', format(master,'020x'))
    for i,(pt,ct) in enumerate(pairs):
        print(i, enc5_with_rks(pt,rks)==ct)