#!/usr/bin/env python3
"""BRC-188 v1 deterministic vectors and verifier; keys 1,2,3 are synthetic."""
import hashlib,json,os
P=2**256-2**32-977;N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;G=(55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424)
def A(a,b):
 if a is None:return b
 if b is None:return a
 if a[0]==b[0] and (a[1]+b[1])%P==0:return None
 m=((3*a[0]*a[0])*pow(2*a[1],-1,P) if a==b else (b[1]-a[1])*pow(b[0]-a[0],-1,P))%P;x=(m*m-a[0]-b[0])%P;return x,(m*(a[0]-x)-a[1])%P
def M(k,a=G):
 r=None
 while k:
  if k&1:r=A(r,a)
  a=A(a,a);k>>=1
 return r
def pub(k):x,y=M(k);return bytes([2+y%2])+x.to_bytes(32,'big')
def sig(b,k):
 z=int.from_bytes(hashlib.sha256(b).digest(),'big');q=(z+k)%N or 1;r=M(q)[0]%N;s=pow(q,-1,N)*(z+r*k)%N;s=min(s,N-s);return r.to_bytes(32,'big')+s.to_bytes(32,'big')
def ver(b,s,key):
 if len(s)!=64:return False
 r,x=int.from_bytes(s[:32],'big'),int.from_bytes(s[32:],'big')
 if not(0<r<N and 0<x<=N//2) or len(key)!=33 or key[0] not in(2,3):return False
 X=int.from_bytes(key[1:],'big');Y=pow((X**3+7)%P,(P+1)//4,P);
 if X>=P or Y*Y%P!=(X**3+7)%P:return False
 Y=Y if Y%2==key[0]%2 else P-Y;z=int.from_bytes(hashlib.sha256(b).digest(),'big');q=A(M(z*pow(x,-1,N)%N),M(r*pow(x,-1,N)%N,(X,Y)));return q is not None and q[0]%N==r

# Test-only signing uses public synthetic keys and a deliberately simple nonce.
# NEVER use this signer or its nonce construction with real private keys.
D={1:b'BSV-GROUP-GENESIS\0',2:b'BSV-GROUP-EPOCH\0',16:b'BSV-GROUP-CONTENT\0'}
def H(b):return hashlib.sha256(b).digest()
def u(n,size):return n.to_bytes(size,'big')
def seal(b,k):return b+sig(D[b[4]]+b,k)
def roster(keys,meta=b'demo'):
 return u(len(keys),2)+b''.join(keys)+u(len(meta),4)+meta
def genesis(keys):return seal(b'BGM1\x01'+pub(1)+bytes(range(32))+roster(keys),1)
def epoch(gid,n,prev,keys,meta=b'demo',signer=1):
 return seal(b'BGM1\x02'+gid+u(n,4)+prev+roster(keys,meta),signer)
def content(gid,n,prev,signer=1,body=b'hello',ident=b'0123456789abcdef',typ=1):
 return seal(b'BGM1\x10'+gid+u(n,4)+prev+pub(signer)+ident+bytes([typ])+u(len(body),4)+body,signer)
class Reader:
 def __init__(self,b):self.b=b;self.i=0
 def take(self,n):
  if self.i+n>len(self.b):raise ValueError('truncated')
  v=self.b[self.i:self.i+n];self.i+=n;return v
 def num(self,n):return int.from_bytes(self.take(n),'big')
def key_ok(k):
 if len(k)!=33 or k[0] not in (2,3):raise ValueError('key')
 x=int.from_bytes(k[1:],'big');y=pow((x*x*x+7)%P,(P+1)//4,P)
 if x>=P or y*y%P!=(x*x*x+7)%P:raise ValueError('point')
def parse(frame,creator=None):
 if len(frame)>1048576 or len(frame)<69:raise ValueError('size')
 r=Reader(frame[:-64]);o={}
 if r.take(4)!=b'BGM1':raise ValueError('magic')
 t=r.num(1);o['type']=t
 if t not in D:raise ValueError('type')
 if t==1:
  o['creator']=r.take(33);key_ok(o['creator']);r.take(32)
  o['gid']=H(frame[:-64]);o['epoch']=0;signer=o['creator']
 else:
  o['gid']=r.take(32);o['epoch']=r.num(4);o['prev']=r.take(32)
  signer=creator
 if t in (1,2):
  n=r.num(2)
  if not 1<=n<=256:raise ValueError('roster count')
  keys=[r.take(33) for _ in range(n)]
  for k in keys:key_ok(k)
  if keys!=sorted(set(keys)) or signer not in keys:raise ValueError('roster')
  o['keys']=keys;size=r.num(4)
  if size>4096:raise ValueError('metadata')
  o['metadata']=r.take(size).decode('utf8')
 else:
  signer=r.take(33);key_ok(signer);o['sender']=signer;o['id']=r.take(16)
  typ=r.num(1);size=r.num(4);o['body']=r.take(size)
  if typ not in (1,2):raise ValueError('content type')
  if typ==1:o['body'].decode('utf8')
 if r.i!=len(r.b):raise ValueError('trailing')
 if signer is None or not ver(D[t]+r.b,frame[-64:],signer):raise ValueError('signature')
 o['hash']=H(r.b);return o
class State:
 # Models authenticated inner frames only. BRC-78 outer identities are supplied
 # by a caller that has already decrypted/validated the real outer envelope.
 def __init__(self,g,expected,local):
  o=parse(g)
  if o['creator']!=expected or local not in o['keys']:raise ValueError('join')
  self.creator=expected;self.local=local;self.gid=o['gid'];self.n=0
  self.history={0:o};self.seen={};self.frozen=False
 def control(self,b):
  if self.frozen:raise ValueError('frozen')
  o=parse(b,self.creator);n=o['epoch']
  if o['type']!=2 or o['gid']!=self.gid or n==0:raise ValueError('epoch')
  if n in self.history:
   if o['hash']==self.history[n]['hash']:return 'duplicate'
   self.frozen=True;raise ValueError('fork frozen')
  if n!=self.n+1:raise ValueError('sync needed')
  if o['prev']!=self.history[self.n]['hash']:raise ValueError('predecessor')
  self.history[n]=o;self.n=n;return 'accepted'
 def receive(self,b,outer_sender,outer_recipient):
  if self.frozen:raise ValueError('frozen')
  o=parse(b,self.creator);current=self.history[self.n]
  if o['type']!=16 or o['gid']!=self.gid:raise ValueError('group')
  if o['epoch']>self.n:raise ValueError('sync needed')
  if o['epoch']!=self.n or o['prev']!=current['hash']:raise ValueError('stale/hash')
  if o['sender']!=outer_sender or outer_recipient!=self.local:raise ValueError('outer identity')
  if o['sender'] not in current['keys'] or self.local not in current['keys']:raise ValueError('membership')
  key=(self.gid,o['sender'],o['id'])
  if key in self.seen:
   if self.seen[key]==o['hash']:return 'duplicate'
   raise ValueError('sender equivocation')
  self.seen[key]=o['hash'];return 'accepted'
def main():
 path=os.path.join(os.path.dirname(__file__),'0188-vectors.json')
 keys=[pub(i) for i in (1,2,3)];g=genesis(sorted(keys[:2]));gid=H(g[:-64])
 e1=epoch(gid,1,gid,sorted(keys));e2=epoch(gid,2,H(e1[:-64]),sorted(keys[:2]));e3=epoch(gid,3,H(e2[:-64]),sorted(keys[:2]),b'new label')
 m=content(gid,1,H(e1[:-64]));fixtures={'genesis':g,'add':e1,'remove':e2,'metadata':e3,'content':m}
 data={name:{'frame':b.hex(),'unsignedHash':H(b[:-64]).hex()} for name,b in fixtures.items()}
 if '--generate' in __import__('sys').argv:
  with open(path,'w') as f:json.dump({'warning':'PUBLIC SYNTHETIC PRIVATE KEYS 1,2,3; NEVER FOR PRODUCTION','vectors':data},f,indent=2);f.write('\n')
 with open(path) as f:assert json.load(f)['vectors']==data
 checks=[]
 def reject(name,fn):
  try:fn()
  except (ValueError,UnicodeError):checks.append(name);return
  raise AssertionError('accepted '+name)
 st=State(g,keys[0],keys[1]);assert st.control(e1)=='accepted';assert st.control(e1)=='duplicate'
 assert st.receive(m,keys[0],keys[1])=='accepted';assert st.receive(m,keys[0],keys[1])=='duplicate'
 # Distinct valid low-S ECDSA signatures do not change unsigned content identity.
 z=int.from_bytes(H(D[16]+m[:-64]),'big');nonce=123456789;r=M(nonce)[0]%N
 ss=pow(nonce,-1,N)*(z+r)%N;ss=min(ss,N-ss)
 alternate=m[:-64]+u(r,32)+u(ss,32)
 assert alternate!=m and st.receive(alternate,keys[0],keys[1])=='duplicate'
 reject('changed message ID payload',lambda:st.receive(content(gid,1,H(e1[:-64]),body=b'other'),keys[0],keys[1]))
 reject('outer sender',lambda:st.receive(m,keys[2],keys[1]))
 reject('outer recipient',lambda:st.receive(m,keys[0],keys[2]))
 reject('future content',lambda:st.receive(content(gid,2,H(e2[:-64])),keys[0],keys[1]))
 assert st.control(e2)=='accepted'
 reject('old content',lambda:st.receive(m,keys[0],keys[1]))
 reject('removed sender',lambda:st.receive(content(gid,2,H(e2[:-64]),signer=3),keys[2],keys[1]))
 reject('wrong epoch hash',lambda:st.receive(content(gid,2,bytes(32)),keys[0],keys[1]))
 reject('wrong content group',lambda:st.receive(content(bytes(32),2,H(e2[:-64])),keys[0],keys[1]))
 assert st.control(e3)=='accepted'
 reject('old fork freezes',lambda:st.control(epoch(gid,1,gid,sorted(keys),b'fork')));assert st.frozen
 reject('frozen sends',lambda:st.receive(content(gid,3,H(e3[:-64])),keys[0],keys[1]))
 fresh=lambda:State(g,keys[0],keys[1])
 reject('wrong expected creator',lambda:State(g,keys[1],keys[1]))
 reject('nonmember join',lambda:State(g,keys[0],keys[2]))
 reject('wrong creator signature',lambda:fresh().control(epoch(gid,1,gid,sorted(keys),signer=2)))
 reject('wrong group',lambda:fresh().control(epoch(bytes(32),1,gid,sorted(keys))))
 reject('wrong predecessor',lambda:fresh().control(epoch(gid,1,bytes(32),sorted(keys))))
 reject('gap',lambda:fresh().control(e2))
 reject('epoch zero',lambda:fresh().control(epoch(gid,0,gid,sorted(keys))))
 reject('duplicate roster',lambda:parse(genesis([keys[0],keys[0]])))
 reject('unsorted roster',lambda:parse(genesis(sorted(keys[:2],reverse=True))))
 reject('creator removed',lambda:fresh().control(epoch(gid,1,gid,[keys[1]])))
 reject('empty roster',lambda:parse(genesis([])))
 reject('oversized roster',lambda:parse(genesis([keys[0]]*257)))
 reject('invalid point',lambda:parse(genesis(sorted([keys[0],b'\x02'+b'\xff'*32]))))
 reject('trailing bytes',lambda:parse(seal(g[:-64]+b'junk',1)))
 reject('truncated',lambda:parse(g[:-1]))
 reject('wrong domain',lambda:parse(g[:-64]+sig(D[2]+g[:-64],1)))
 reject('bad signature',lambda:parse(g[:-64]+bytes(64)))
 reject('high S',lambda:parse(g[:-32]+u(N-int.from_bytes(g[-32:],'big'),32)))
 reject('metadata UTF8',lambda:fresh().control(epoch(gid,1,gid,sorted(keys),b'\xff')))
 reject('metadata limit',lambda:fresh().control(epoch(gid,1,gid,sorted(keys),b'a'*4097)))
 reject('body UTF8',lambda:parse(content(gid,1,gid,body=b'\xff')))
 reject('content type',lambda:parse(content(gid,1,gid,typ=3)))
 reject('frame limit',lambda:parse(content(gid,1,gid,body=b'a'*1048576)))
 assert parse(content(gid,1,gid,body=b'\xff',typ=2))['body']==b'\xff'
 print('PASS: 5 signed fixtures, add/remove/metadata/replay transitions, '+str(len(checks))+' exercised rejections; no outer encryption or chain verification')
if __name__=='__main__':main()
