from pathlib import Path
import math, itertools, time
from heapq import nlargest
import sys
import time

st = time.time()

def permute(x, table, inbits):
    y=0
    for pos in table:
        y=(y<<1)|((x>>(inbits-pos))&1)
    return y

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

# fast DES5 preout
Epos=[E[i*6:(i+1)*6] for i in range(8)]
SP=[[0]*64 for _ in range(8)]
for j in range(8):
    for six in range(64):
        row=((six>>5)&1)*2+(six&1)
        col=(six>>1)&0xf
        y=SBOX[j][row][col]
        SP[j][six]=permute(y<<(28-4*j),P,32)

def get6(R,pos6):
    v=0
    for p in pos6:
        v=(v<<1)|((R>>(32-p))&1)
    return v

def f_fast(R,K48):
    out=0
    for j in range(8):
        six=get6(R,Epos[j]) ^ ((K48>>(42-6*j))&0x3f)
        out ^= SP[j][six]
    return out

def rotl28(x,s):
    return ((x<<s)&0xfffffff) | (x>>(28-s))

def rotr28(x,s):
    return ((x>>s) | ((x & ((1<<s)-1))<<(28-s))) & 0xfffffff

def subkeys5_from_key56_int(key56):
    C=(key56>>28)&0xfffffff
    D=key56&0xfffffff
    ks=[]
    for r in range(5):
        C=rotl28(C,SHIFTS[r]); D=rotl28(D,SHIFTS[r])
        ks.append(permute((C<<28)|D,PC2,56))
    return ks

def des5_preout(ip_pt, ks5):
    L=(ip_pt>>32)&0xffffffff
    R=ip_pt&0xffffffff
    for K in ks5:
        L,R=R, L ^ f_fast(R,K)
    return (R<<32)|L

def des5_encrypt_full(pt,key64):
    key56=permute(key64,PC1,64)
    ks5=subkeys5_from_key56_int(key56)
    ip=permute(pt,IP,64)
    pre=des5_preout(ip,ks5)
    return permute(pre,FP,64)

assert des5_encrypt_full(int('1111111111111111',16),int('0123456789abcdef',16))==int('c675c5aa73468cdb',16)

# Beam search precompute LAT and ET
LAT=[]
for sb in range(8):
    corr=[[0.0]*16 for _ in range(64)]
    for a in range(64):
        for b in range(16):
            s=0
            for x in range(64):
                row=((x>>5)&1)*2+(x&1)
                col=(x>>1)&0xf
                y=SBOX[sb][row][col]
                s += 1 if (((a&x).bit_count() ^ (b&y).bit_count())&1)==0 else -1
            corr[a][b]=s/64.0
    LAT.append(corr)

Pinv_table=[0]*32
for i,pos in enumerate(P):
    Pinv_table[pos-1]=i+1

def split_sbox_out_masks(v32):
    beforeP=permute(v32,Pinv_table,32)
    return [ (beforeP>>(28-4*j))&0xf for j in range(8) ]

pos_for_r=[[] for _ in range(33)]
for k,src in enumerate(E, start=1):
    pos_for_r[src].append(k)

def ET_single(j,a6):
    a48=0
    for t in range(6):
        if (a6>>(5-t))&1:
            k=j*6+t+1
            a48 |= 1<<(48-k)
    m=0
    for r in range(1,33):
        parity=0
        for k in pos_for_r[r]:
            parity ^= (a48>>(48-k))&1
        if parity:
            m |= 1<<(32-r)
    return m

m_contrib=[[ET_single(j,a) for a in range(64)] for j in range(8)]

from heapq import nlargest

def beam_search(u4,v4=0,max_active=4,beam=2000,topA=6):
    states={(u4,v4):0.0}
    for _ in range(4):
        new={}
        for (u,v),logc in states.items():
            if v==0:
                m_candidates=[(0,1.0)]
            else:
                bjs=split_sbox_out_masks(v)
                active=[idx for idx,bj in enumerate(bjs) if bj]
                if len(active)>max_active:
                    continue
                per=[]
                for jj in active:
                    bj=bjs[jj]
                    lst=[(abs(LAT[jj][a][bj]),LAT[jj][a][bj],a) for a in range(64) if LAT[jj][a][bj]!=0]
                    if not lst:
                        per=None
                        break
                    lst.sort(reverse=True)
                    per.append((jj,lst[:topA]))
                if per is None:
                    continue
                m_candidates=[]
                for prod in itertools.product(*[p[1] for p in per]):
                    m=0; c=1.0
                    for (jj,_),(_,cc,a) in zip(per,prod):
                        m ^= m_contrib[jj][a]
                        c *= cc
                    if c!=0:
                        m_candidates.append((m,c))
            for m,c in m_candidates:
                ab=abs(c)
                if ab==0: continue
                prev=(v, u ^ m)
                log_new=logc+math.log2(ab)
                if prev not in new or log_new>new[prev]:
                    new[prev]=log_new
        if not new:
            return None
        if len(new)>beam:
            new=dict(nlargest(beam,new.items(),key=lambda kv: kv[1]))
        states=new
    (u0,v0),logc=max(states.items(),key=lambda kv: kv[1])
    return u0,v0,logc

# u4 for two sboxes with masks b1=b2=15

def u4_two(j1,j2):
    beforeP=(15<<(28-4*j1)) | (15<<(28-4*j2))
    return permute(beforeP,P,32)

# parity lookups po[j][x^k]
po=[[0]*64 for _ in range(8)]
for j in range(8):
    for x in range(64):
        row=((x>>5)&1)*2+(x&1)
        col=(x>>1)&0xf
        po[j][x]=(SBOX[j][row][col] & 15).bit_count()&1

# Load pairs


# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from DES import supreme_encryption
N = 350000 # number of plaintext-ciphetext pairs used
SECRET_KEY = "e21304006ba619cc"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 5, "")
    pairs.append((int(pt, 16), int(ct, 16)))
print('N',N)

L0=[0]*N; R0=[0]*N; R5=[0]*N; ER4=[0]*N
for i,(pt,ct) in enumerate(pairs):
    ipt=permute(pt,IP,64)
    L0[i]=(ipt>>32)&0xffffffff
    R0[i]=ipt&0xffffffff
    ipc=permute(ct,IP,64)
    R5[i]=(ipc>>32)&0xffffffff
    R4=ipc&0xffffffff
    ER4[i]=permute(R4,E,32)

def parity_mask(x,mask):
    return ((x & mask).bit_count()&1)

# unknown bit deltas (as before)
invPC2=[None]*56
for out_idx,src_pos in enumerate(PC2, start=1):
    invPC2[src_pos-1]=out_idx
unk_cd5=[pos for pos in range(56) if invPC2[pos] is None]
unk_key56_masks=[]
for pos in unk_cd5:
    CD5=1<<(55-pos)
    C5=(CD5>>28)&0xfffffff
    D5=CD5&0xfffffff
    unk_key56_masks.append((rotr28(C5,8)<<28)|rotr28(D5,8))

delta=[[0]*5 for _ in range(8)]
for t,mask56 in enumerate(unk_key56_masks):
    ks=subkeys5_from_key56_int(mask56)
    for r in range(5):
        delta[t][r]=ks[r]
DeltaByG=[[0]*5 for _ in range(256)]
for g in range(256):
    arr=[0]*5
    for t in range(8):
        if (g>>(7-t))&1:
            for r in range(5):
                arr[r]^=delta[t][r]
    DeltaByG[g]=arr

# recover group candidates
TOPK=20
groups=[(0,1),(2,3),(4,5),(6,7)]
TopK12=[]

for (a,b) in groups:
    u4=u4_two(a,b)
    u0,v0,logc=beam_search(u4,0)
    print('group',a+1,b+1,'logc',logc)
    shA=42-6*a; shB=42-6*b
    counts0=[[0]*64 for _ in range(64)]
    counts1=[[0]*64 for _ in range(64)]
    for i in range(N):
        c=parity_mask(L0[i],u0)^parity_mask(R0[i],v0)^parity_mask(R5[i],u4)
        xA=(ER4[i]>>shA)&0x3f
        xB=(ER4[i]>>shB)&0x3f
        if c==0: counts0[xA][xB]+=1
        else: counts1[xA][xB]+=1
    rowtot0=[sum(counts0[xA]) for xA in range(64)]
    rowtot1=[sum(counts1[xA]) for xA in range(64)]

    score_mat=[[0.0]*64 for _ in range(64)]
    # score all keys
    for kB in range(64):
        pb_bits=[po[b][xB^kB] for xB in range(64)]
        A0term=[0]*64
        diff=[0]*64
        for xA in range(64):
            sum0_B1=0; sum1_B1=0
            r0=counts0[xA]; r1=counts1[xA]
            for xB in range(64):
                if pb_bits[xB]:
                    sum0_B1+=r0[xB]
                    sum1_B1+=r1[xB]
            s00=rowtot0[xA]-sum0_B1
            s01=sum0_B1
            s10=rowtot1[xA]-sum1_B1
            s11=sum1_B1
            a0=s00+s11
            a1=s01+s10
            A0term[xA]=a0
            diff[xA]=a1-a0
        base_sumA0=sum(A0term)
        for kA in range(64):
            add=0
            for xA in range(64):
                if po[a][xA^kA]:
                    add += diff[xA]
            cnt0=base_sumA0+add
            dev=abs(cnt0-N/2)
            score_mat[kA][kB]=dev

    flat=[]
    for kA in range(64):
        for kB in range(64):
            flat.append(((kA<<6)|kB, score_mat[kA][kB]))
    flat.sort(key=lambda t:t[1], reverse=True)
    top=[k for k,s in flat[:TOPK]]
    TopK12.append(top)
    print(' top candidates',top[:5])

# brute over candidates
check_pairs=[(permute(pt,IP,64),permute(ct,IP,64)) for pt,ct in pairs[:3]]
ip_pt0,ip_ct0=check_pairs[0]

def base_from_K5(K5):
    CD5=0
    for pos in range(56):
        out=invPC2[pos]
        bit=0
        if out is not None:
            bit=(K5>>(48-out))&1
        CD5=(CD5<<1)|bit
    C5=(CD5>>28)&0xfffffff
    D5=CD5&0xfffffff
    key56=(rotr28(C5,8)<<28)|rotr28(D5,8)
    return key56, subkeys5_from_key56_int(key56)

start=time.time()
final=None
for K12s in itertools.product(*TopK12):
    K5=0
    for K12 in K12s:
        K5=(K5<<12)|K12
    base_key56, base_ks5 = base_from_K5(K5)
    for g in range(256):
        ks5=[base_ks5[r]^DeltaByG[g][r] for r in range(5)]
        if des5_preout(ip_pt0,ks5)!=ip_ct0:
            continue
        ok=True
        for ip_pt,ip_ct in check_pairs[1:]:
            if des5_preout(ip_pt,ks5)!=ip_ct:
                ok=False
                break
        if ok:
            key56=base_key56
            for t in range(8):
                if (g>>(7-t))&1:
                    key56 ^= unk_key56_masks[t]
            final=key56
            break
    if final is not None:
        break
print('brute time',time.time()-start,'found',final is not None)

if final is not None:
    invPC1=[None]*64
    for out_idx,src_pos in enumerate(PC1, start=1):
        invPC1[src_pos-1]=out_idx
    key64=0
    for pos in range(64):
        out=invPC1[pos]
        bit=0 if out is None else ((final>>(56-out))&1)
        key64=(key64<<1)|bit
    print('key64',hex(key64))
    for i,(pt,ct) in enumerate(pairs[:3]):
        print('verify',i, des5_encrypt_full(pt,key64)==ct)

et = time.time()
print(f"TOTAL TIME: {et-st}")