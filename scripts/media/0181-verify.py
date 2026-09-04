import hashlib,json,sys
from pathlib import Path
# Independent stdlib secp256k1 arithmetic; only verifies public fixtures.
P=2**256-2**32-977
N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G=(55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424)
def add(a,b):
 if a is None:return b
 if b is None:return a
 if a[0]==b[0] and (a[1]+b[1])%P==0:return None
 m=((3*a[0]*a[0])*pow(2*a[1],-1,P) if a==b else (b[1]-a[1])*pow(b[0]-a[0],-1,P))%P
 x=(m*m-a[0]-b[0])%P;return x,(m*(a[0]-x)-a[1])%P
def mul(k,a=G):
 r=None
 while k:
  if k&1:r=add(r,a)
  a=add(a,a);k>>=1
 return r
def sha(b):return hashlib.sha256(b).digest()
def dsha(b):return sha(sha(b))
def compact(n):
 if n<253:return bytes([n])
 if n<=65535:return b'\xfd'+n.to_bytes(2,'little')
 return b'\xfe'+n.to_bytes(4,'little')
def address(q,compressed):
 x,y=q;b=(bytes([2+y%2])+x.to_bytes(32,'big')) if compressed else b'\x04'+x.to_bytes(32,'big')+y.to_bytes(32,'big')
 body=b'\0'+hashlib.new('ripemd160',sha(b)).digest();data=body+dsha(body)[:4];n=int.from_bytes(data,'big');s=''
 while n:n,r=divmod(n,58);s='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[r]+s
 return '1'*(len(data)-len(data.lstrip(b'\0')))+s

def verify(message,sig,addr):
 if len(sig)!=65 or not 27<=sig[0]<=34:return False
 rec=(sig[0]-27)&3;r=int.from_bytes(sig[1:33],'big');s=int.from_bytes(sig[33:],'big')
 if not 0<r<N or not 0<s<N:return False
 x=r+(rec>>1)*N
 if x>=P:return False
 y=pow((x**3+7)%P,(P+1)//4,P)
 if y*y%P!=(x**3+7)%P:return False
 if y%2!=(rec&1):y=P-y
 z=int.from_bytes(dsha(b'\x18Bitcoin Signed Message:\n'+compact(len(message))+message),'big')
 q=mul(pow(r,-1,N),add(mul(s,(x,y)),mul((-z)%N)))
 if q is None:return False
 check=add(mul(z*pow(s,-1,N)%N),mul(r*pow(s,-1,N)%N,q))
 return check is not None and check[0]%N==r and address(q,bool((sig[0]-27)&4))==addr
class Reader:
 def __init__(self,b):self.b=b;self.i=0
 def take(self,n):
  if self.i+n>len(self.b):raise ValueError('truncated')
  v=self.b[self.i:self.i+n];self.i+=n;return v
 def num(self,n):return int.from_bytes(self.take(n),'little')
 def var(self):
  x=self.num(1);return x if x<253 else self.num({253:2,254:4,255:8}[x])
def outputs(raw):
 r=Reader(raw);r.take(4)
 for _ in range(r.var()):r.take(36);r.take(r.var());r.take(4)
 out=[]
 for _ in range(r.var()):r.take(8);out.append(r.take(r.var()))
 r.take(4);assert r.i==len(raw);return out
def pushes(script):
 # Historical OP_RETURN and OP_FALSE OP_RETURN carriers. Decode opcodes.
 r=Reader(script)
 if script.startswith(b'\0\x6a'):r.take(2)
 elif script.startswith(b'\x6a'):r.take(1)
 else:return []
 fields=[b'\x6a']
 while r.i<len(script):
  op=r.num(1)
  if op<=75:size=op
  elif op in (76,77,78):size=r.num({76:1,77:2,78:4}[op])
  else:raise ValueError('non-push')
  fields.append(r.take(size))
 return fields
PREFIX=b'15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva'
def inspect(path):
 raw=bytes.fromhex(Path(path).read_text().strip());result=[]
 for vout,script in enumerate(outputs(raw)):
  f=pushes(script)
  for i,x in enumerate(f):
   if x!=PREFIX or f[i-1]!=b'|':continue
   end=next((j for j in range(i+1,len(f)) if f[j]==b'|'),len(f));tail=f[i+4:end]
   indices=[int.from_bytes(b,'big') for b in tail] if tail else list(range(i))
   assert all(b for b in tail) and all(j<i for j in indices)
   message=b''.join(f[j] for j in indices);sig=f[i+3];addr=f[i+2].decode()
   assert f[i+1]==b'BITCOIN_ECDSA'
   assert verify(message,sig,addr),(vout,i,addr,indices,message.hex())
   assert not verify(message+b'x',sig,addr)
   result.append(dict(vout=vout,prefixIndex=i,signatureHex=sig.hex(),address=addr,indexPayloads=[x.hex() for x in tail],selectedIndexes=indices,messageHex=message.hex(),digestHex=dsha(b'\x18Bitcoin Signed Message:\n'+compact(len(message))+message).hex()))
 return dict(txid=dsha(raw)[::-1].hex(),rawHex=raw.hex(),signatures=result)
if __name__=='__main__':
 import tempfile
 data=json.loads(Path(__file__).with_name('0181-vectors.json').read_text())
 count=0
 for expected in data['transactions']:
  with tempfile.NamedTemporaryFile(mode='w+',suffix='.hex') as f:
   f.write(expected['rawHex']);f.flush();actual=inspect(f.name)
  assert actual==expected
  count+=len(actual['signatures'])
 assert count==3
 print('PASS: 2 raw transaction hashes, 3 historical AIP signatures and changed-message rejection; no chain inclusion verification')
