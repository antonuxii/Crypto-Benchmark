import time, math, itertools, heapq

t0=time.time()
# tables (minimal)
IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
FP=[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E=[32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2=[14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
SHIFTS=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
SBOX=[
[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

def permute(x, table, in_bits):
    out=0
    for pos in table:
        out=(out<<1) | ((x>>(in_bits-pos))&1)
    return out

def invert_perm(table):
    inv=[0]*len(table)
    for out_i,in_pos in enumerate(table, start=1):
        inv[in_pos-1]=out_i
    return inv
P_INV=invert_perm(P)
FP_INV=invert_perm(FP)
MASK28=(1<<28)-1

def rotr28(x,s):
    return ((x>>s) | ((x & ((1<<s)-1)) << (28-s))) & MASK28

from pathlib import Path
import sys

# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from DES import supreme_encryption
N = 50000 # number of plaintext-ciphetext pairs used
SECRET_KEY = "75bfa3fe3e8d1d87"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 4, "")
    pairs.append((int(pt, 16), int(ct, 16)))

N=len(pairs)
print('loaded',N,'t',time.time()-t0)

# per-pair arrays
L0=[0]*N; R0=[0]*N; R4=[0]*N; R5=[0]*N
for i,(pt,ct) in enumerate(pairs):
    ip=permute(pt,IP,64)
    L0[i]=(ip>>32)&0xffffffff
    R0[i]=ip&0xffffffff
    pre=permute(ct,FP_INV,64)
    R5[i]=(pre>>32)&0xffffffff
    R4[i]=pre & 0xffffffff

# LAT
LAT=[[[0]*16 for _ in range(64)] for __ in range(8)]
for si in range(8):
    Sx=[0]*64
    for x in range(64):
        row=((x&0x20)>>4)|(x&1); col=(x>>1)&0xf
        Sx[x]=SBOX[si][row][col]
    for a in range(64):
        for b in range(16):
            s=0
            for x in range(64):
                s += 1 if (((a&x).bit_count() ^ (b&Sx[x]).bit_count()) & 1)==0 else -1
            LAT[si][a][b]=s

# E transpose
exp_bit_masks=[1<<(32-pos) for pos in E]

def E_transpose_mask(a48):
    m=0
    while a48:
        lsb=a48 & -a48
        idx=lsb.bit_length()-1
        m ^= exp_bit_masks[47-idx]
        a48 ^= lsb
    return m

# best m for n (max_active=2)

def best_m_for_n(n, max_active=2, per_box_keep=12):
    if n==0:
        return 0
    v=permute(n,P_INV,32)
    active=[]
    for j in range(8):
        bm=(v>>(4*(7-j)))&0xF
        if bm:
            active.append((j,bm))
    if len(active)>max_active:
        return 0
    per=[]
    for j,bm in active:
        ch=[(a,LAT[j][a][bm]) for a in range(64) if LAT[j][a][bm]!=0]
        ch.sort(key=lambda t: abs(t[1]), reverse=True)
        per.append((j,ch[:per_box_keep]))
    bestm=0; bestlog=-999
    for combo in itertools.product(*[c for _,c in per]):
        a48=0; logabs=0.0
        for (j,(a,corr)) in zip([j for j,_ in per], combo):
            a48 |= (a&0x3f) << (6*(7-j))
            logabs += math.log2(abs(corr)) - 6.0
        m=E_transpose_mask(a48)
        if logabs>bestlog:
            bestlog=logabs; bestm=m
    return bestm

# E positions for expand6
Epos=[[E[6*j+t] for t in range(6)] for j in range(8)]

def expand6_sbox(r32,j):
    out=0
    for pos in Epos[j]:
        out=(out<<1)|((r32>>(32-pos))&1)
    return out

# trails and rank lists
TOPC=8
ranked_lists=[]
for j in range(8):
    b=0xF
    A4=permute(b << (4*(7-j)), P, 32)
    B4=A4
    Ai,Bi=A4,B4
    for _ in range(4):
        m=best_m_for_n(Bi)
        Ai,Bi = (Bi & 0xffffffff), (m ^ Ai) & 0xffffffff
    A0,B0=Ai,Bi
    parity_s=[0]*64
    for x in range(64):
        row=((x&0x20)>>4)|(x&1); col=(x>>1)&0xf
        parity_s[x]=(b & SBOX[j][row][col]).bit_count()&1
    counts=[[0,0] for _ in range(64)]
    for i in range(N):
        tb = (((A0&L0[i]).bit_count() ^ (B0&R0[i]).bit_count() ^ (B4&R4[i]).bit_count() ^ (A4&R5[i]).bit_count()) & 1)
        v=expand6_sbox(R4[i], j)
        counts[v][tb]+=1
    half=N/2.0
    devs=[]
    for k in range(64):
        ones=0
        for v in range(64):
            ps=parity_s[v^k]
            ones += counts[v][0]*ps + counts[v][1]*(1-ps)
        devs.append((abs(ones-half),k))
    devs.sort(reverse=True)
    ranked=[k for _,k in devs[:TOPC]]
    ranked_lists.append(ranked)

print('rank lists done t',time.time()-t0)

# fast key test on first pair
pt0,ct0=pairs[0]
ip0=permute(pt0,IP,64)
L_init=(ip0>>32)&0xffffffff
R_init=ip0&0xffffffff
pre_target=permute(ct0,FP_INV,64)

SP=[[0]*64 for _ in range(8)]
for si in range(8):
    for x in range(64):
        row=((x&0x20)>>4)|(x&1); col=(x>>1)&0xf
        s=SBOX[si][row][col]
        SP[si][x]=permute(s << (4*(7-si)), P, 32)


def f_fast(r32,k48):
    out=0
    for si in range(8):
        e6=0
        base=6*si
        for t in range(6):
            pos=E[base+t]
            e6=(e6<<1)|((r32>>(32-pos))&1)
        out ^= SP[si][e6 ^ ((k48>>(42-6*si))&0x3f)]
    return out & 0xffffffff


def pc2_select(cd56):
    out=0
    for pos in PC2:
        out=(out<<1) | ((cd56>>(56-pos))&1)
    return out


def subkeys5(k56):
    c=(k56>>28)&MASK28
    d=k56&MASK28
    subs=[]
    for r in range(5):
        sh=SHIFTS[r]
        c=((c<<sh)&MASK28) | (c>>(28-sh))
        d=((d<<sh)&MASK28) | (d>>(28-sh))
        subs.append(pc2_select((c<<28)|d))
    return subs


def enc_pre(k56):
    subs=subkeys5(k56)
    l=L_init; r=R_init
    for i in range(5):
        l,r=r,(l ^ f_fast(r, subs[i])) & 0xffffffff
    return (r<<32)|l

unknown_positions=[i for i in range(56) if i+1 not in PC2]

def try_K5(K5):
    bits=[None]*56
    for out_i,in_pos in enumerate(PC2):
        bits[in_pos-1]=(K5>>(47-out_i))&1
    for mask in range(256):
        for t,pos in enumerate(unknown_positions):
            bits[pos]=(mask>>(7-t))&1
        cd=0
        for bit in bits:
            cd=(cd<<1)|bit
        C5=(cd>>28)&MASK28; D5=cd&MASK28
        k56=(rotr28(C5,8)<<28)|rotr28(D5,8)
        if enc_pre(k56)==pre_target:
            return k56
    return None

# best-first rank sum <=12
heap=[(0,(0,0,0,0,0,0,0,0))]; seen={heap[0][1]}
found=None
while heap:
    s,ranks=heapq.heappop(heap)
    if s>12: break
    K5=0
    for j,ri in enumerate(ranks):
        K5=(K5<<6)|ranked_lists[j][ri]
    k56=try_K5(K5)
    if k56 is not None:
        found=(k56,K5,ranks); break
    for j in range(8):
        if ranks[j]+1<TOPC:
            nr=list(ranks); nr[j]+=1; nr=tuple(nr)
            if nr not in seen:
                seen.add(nr)
                heapq.heappush(heap,(s+1,nr))

print('search end found',found is not None,'t',time.time()-t0)
if found:
    k56,K5,ranks=found
    # verify 3 pairs
    def des5(pt,k56):
        ip=permute(pt,IP,64)
        l=(ip>>32)&0xffffffff
        r=ip&0xffffffff
        subs=subkeys5(k56)
        for i in range(5):
            l,r=r,(l ^ f_fast(r,subs[i])) & 0xffffffff
        return permute((r<<32)|l,FP,64)
    ok=[des5(pairs[i][0],k56)==pairs[i][1] for i in range(3)]
    print('verify3',ok)
    # key64
    bits64=[0]*64
    for i,pos in enumerate(PC1, start=1):
        bits64[pos-1]=(k56>>(56-i))&1
    key64=0
    for b in bits64:
        key64=(key64<<1)|b
    print('key64',hex(key64))