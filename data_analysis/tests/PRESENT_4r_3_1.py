'''
SAT attempt from the model. Check if it can ever converge when given more time (3h or so). True key: "5be4393b843ae17d7af6"
We ran it on the athena01 machine afterwards and got the following output:

Using N 8
vars 3680 clauses 40192
sat False
unsat

Failed attempt, independent of sandbox tiemouts.
'''

from pysat.solvers import Cadical153
from pathlib import Path
import sys
import time as time

# Add benchmark/data/ciphers to import path
sys.path.append(str(Path(__file__).resolve().parents[2] / "data" / "ciphers"))

from PRESENT import supreme_encryption

SBOX = [0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2]
P=[0]*64
for i in range(63): P[i]=(16*i)%63
P[63]=63

N = 8 # number of plaintext-ciphetext pairs used
SECRET_KEY = "5be4393b843ae17d7af6"
pairs = []
for _ in range(N):
    pt, ct = supreme_encryption(SECRET_KEY, 2, "")
    pairs.append((int(pt,16), int(ct,16)))
print('Using N',N)

# python verify

def sbox_layer_py(x):
    y=0
    for i in range(16):
        y |= SBOX[(x>>(4*i))&0xF] << (4*i)
    return y

def p_layer_py(x):
    y=0
    for i in range(64):
        y |= ((x>>i)&1) << P[i]
    return y

def round_keys_80_py(key, rounds=4):
    rks=[]
    k=key
    for r in range(1, rounds+2):
        rks.append((k>>16) & ((1<<64)-1))
        if r==rounds+1: break
        k = ((k & ((1<<19)-1))<<61) | (k>>19)
        top=(k>>76)&0xF
        k = (k & ((1<<76)-1)) | (SBOX[top]<<76)
        k ^= (r & 0x1F) << 15
    return rks

def present4_py(pt,key):
    rks=round_keys_80_py(key,4)
    s=pt
    for r in range(4):
        s ^= rks[r]
        s = sbox_layer_py(s)
        s = p_layer_py(s)
    s ^= rks[4]
    return s

# Sbox templates
SBOX_TMPL=[]
for v in range(16):
    in_sign=[1 if ((v>>i)&1)==0 else -1 for i in range(4)]
    outv=SBOX[v]
    for j in range(4):
        out_sign = 1 if ((outv>>j)&1)==1 else -1
        SBOX_TMPL.append(((0,in_sign[0]),(1,in_sign[1]),(2,in_sign[2]),(3,in_sign[3]),(4+j,out_sign)))

# build CNF for all pairs
var=0

def newvar():
    global var
    var+=1
    return var

clauses=[]
append=clauses.append

def add_equiv(a,b):
    append([-a,b]); append([a,-b])

def add_xor(a,b,o):
    append([a,b,-o]); append([-a,-b,-o]); append([a,-b,o]); append([-a,b,o])

def add_sbox(in4,out4):
    w=in4+out4
    for t in SBOX_TMPL:
        append([w[i]*s for i,s in t])

def bits64(x):
    return [(x>>i)&1 for i in range(64)]

K1=[newvar() for _ in range(80)]

def key_update(K,r):
    Rot=[K[(i+19)%80] for i in range(80)]
    out4=[newvar(),newvar(),newvar(),newvar()]
    add_sbox(Rot[76:80], out4)
    Rot[76:80]=out4
    if r & 1:   Rot[15] = -Rot[15]
    if r & 2:   Rot[16] = -Rot[16]
    if r & 4:   Rot[17] = -Rot[17]
    if r & 8:   Rot[18] = -Rot[18]
    if r & 16:  Rot[19] = -Rot[19]
    return Rot

K2=key_update(K1,1); K3=key_update(K2,2); K4=key_update(K3,3); K5=key_update(K4,4)
RK1=K1[16:80]; RK2=K2[16:80]; RK3=K3[16:80]; RK4=K4[16:80]; RK5=K5[16:80]


def do_round(state,rk):
    x=[0]*64
    for i,(a,b) in enumerate(zip(state,rk)):
        if a==0: x[i]=b
        elif a==1: x[i]=-b
        else:
            o=newvar(); add_xor(a,b,o); x[i]=o
    y=[0]*64
    for sbi in range(16):
        out4=[newvar(),newvar(),newvar(),newvar()]
        add_sbox(x[4*sbi:4*sbi+4], out4)
        y[4*sbi:4*sbi+4]=out4
    out=[0]*64
    for i in range(64):
        out[P[i]]=y[i]
    return out

for pt,ct in pairs:
    st=bits64(pt)
    st=do_round(st,RK1); st=do_round(st,RK2); st=do_round(st,RK3); st=do_round(st,RK4)
    cb=bits64(ct)
    for i in range(64):
        add_equiv(st[i], RK5[i] if cb[i]==0 else -RK5[i])

print('vars',var,'clauses',len(clauses))

st = time.time()
with Cadical153(bootstrap_with=clauses) as s:
    ok=s.solve()
    print('sat',ok)
    if not ok: raise SystemExit('unsat')
    model=s.get_model()

val=[False]*(var+1)
for lit in model:
    if lit>0: val[lit]=True
key_val=0
for i,v in enumerate(K1):
    if val[v]: key_val |= 1<<i

et = time.time()

print("TIME", et-st)
print('key', format(key_val,'020x'))

# verify first 3 pairs
for i,(pt,ct) in enumerate(pairs[:3]):
    ct2=present4_py(pt,key_val)
    print('pair',i,'ok?',ct2==ct)

print('all ok?', all(present4_py(pt,key_val)==ct for pt,ct in pairs))