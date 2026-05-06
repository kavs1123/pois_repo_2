/**
 * Bleichenbacher pre-computation with e=3 (tiny) for fast oracle queries.
 * e=3 is a valid RSA public exponent (gcd(3, phi)=1 for most primes).
 * Each oracle call is ~100x faster than e=65537.
 */
import { webcrypto } from 'node:crypto';
const C = webcrypto;

function modPow(b, e, m) {
  if(m===1n)return 0n; b=((b%m)+m)%m; let r=1n;
  while(e>0n){if(e&1n)r=r*b%m;e>>=1n;b=b*b%m;} return r;
}
function extGcd(a,b){if(b===0n)return{g:a,x:1n,y:0n};const{g,x,y}=extGcd(b,a%b);return{g,x:y,y:x-(a/b)*y};}
function modInverse(a,m){const am=((a%m)+m)%m;const{g,x}=extGcd(am,m);if(g!==1n)throw new Error('no inv');return((x%m)+m)%m;}
function gcd(a,b){return b===0n?a:gcd(b,a%b);}
function byteLen(n){return Math.ceil(n.toString(16).length/2);}
function toBytes(n,len){const o=new Uint8Array(len);let v=n;for(let i=len-1;i>=0;i--){o[i]=Number(v&0xffn);v>>=8n;}return o;}
function toInt(b){let v=0n;for(const x of b)v=(v<<8n)|BigInt(x);return v;}
function factorTwos(n){let s=0n,d=n-1n;while(d%2n===0n){d/=2n;s+=1n;}return{s,d};}
function randBig(n){const bits=n.toString(2).length,bytes=Math.ceil(bits/8);while(true){const b=new Uint8Array(bytes);C.getRandomValues(b);if(bits%8!==0)b[0]&=(1<<(bits%8))-1;let v=0n;for(const x of b)v=(v<<8n)|BigInt(x);if(v>=2n&&v<=n-2n)return v;}}
function millerRabin(n,k=20){if(n<2n||n%2n===0n)return false;if(n===2n||n===3n)return true;const{s,d}=factorTwos(n);for(let i=0;i<k;i++){const a=randBig(n);let x=modPow(a,d,n);if(x===1n||x===n-1n)continue;let p=false;for(let r=1n;r<s;r++){x=modPow(x,2n,n);if(x===n-1n){p=true;break;}}if(!p)return false;}return true;}

// Generate prime NOT divisible by (e-1) = 2, meaning p ≡ 2 (mod 3)
function genPrime3(bits){
  const bLen=Math.ceil(bits/8);
  const SMALL=[5n,7n,11n,13n,17n,19n,23n,29n,31n];
  while(true){
    const b=new Uint8Array(bLen);C.getRandomValues(b);b[0]|=0x80;b[bLen-1]|=1;
    let n=0n;for(const x of b)n=(n<<8n)|BigInt(x);
    if(n%3n===0n)continue; // e=3 requires gcd(3, p-1)=1, so p ≢ 1 (mod 3), i.e., p ≡ 2 (mod 3)
    if((n-1n)%3n===0n)continue; // p-1 divisible by 3 means gcd(3,phi) ≠ 1
    let skip=false;for(const p of SMALL){if(n===p)break;if(n%p===0n){skip=true;break;}}
    if(skip)continue;
    if(millerRabin(n))return n;
  }
}
function rsaKeygen3(bits){
  const half=Math.floor(bits/2),e=3n;
  let p,q,N,phi,d;
  while(true){
    p=genPrime3(half);q=genPrime3(half);
    if(p===q)continue;
    N=p*q;phi=(p-1n)*(q-1n);
    if(gcd(e,phi)!==1n)continue;
    d=modInverse(e,phi);
    break;
  }
  return{pk:{N,e},sk:{N,d,p,q}};
}

function pkcs15Enc(pk,mBytes){
  const k=byteLen(pk.N);
  if(mBytes.length>k-11)throw new Error(`msg too long: k=${k}`);
  const psLen=k-mBytes.length-3;
  const ps=new Uint8Array(psLen);let i=0;
  while(i<psLen){const b=new Uint8Array(64);C.getRandomValues(b);for(const x of b){if(x!==0&&i<psLen)ps[i++]=x;}}
  const em=new Uint8Array(k);em[0]=0x00;em[1]=0x02;em.set(ps,2);em[2+psLen]=0x00;em.set(mBytes,3+psLen);
  return{c:modPow(toInt(em),pk.e,pk.N),em};
}
function pkcs15Dec(sk,c){
  const k=byteLen(sk.N);const em=toBytes(modPow(c,sk.d,sk.N),k);
  if(em[0]!==0x00||em[1]!==0x02)return false;
  let i=2;while(i<em.length&&em[i]!==0x00)i++;
  if(i-2<8||i>=em.length)return false;return em;
}

const ceilDiv=(a,b)=>(a+b-1n)/b,floorDiv=(a,b)=>a/b;
const bigMax=(a,b)=>a>b?a:b,bigMin=(a,b)=>a<b?a:b;

function bleichenbacher(pk,c,sk){
  const{N,e}=pk;
  const k=byteLen(N),B=2n**BigInt(8*(k-2)),twoB=2n*B,threeB=3n*B;
  const oracle=ci=>pkcs15Dec(sk,ci)!==false;
  let M=[[twoB,threeB-1n]],s=ceilDiv(N,threeB),total=0,step=0;
  const log=[];const t0=Date.now();

  while(true){
    step++;let local=0;
    while(true){
      total++;local++;
      if(oracle(c*modPow(s,e,N)%N))break;
      s++;
    }
    const ms=Date.now()-t0;
    console.log(`  step ${step}: s found in ${local} tries, total=${total}, elapsed=${ms}ms, intervals=${M.length}`);
    log.push({step,localQueries:local,totalQueries:total,ms});
    
    const newM=[];
    for(const[a,b]of M){const rMin=ceilDiv(a*s-threeB+1n,N),rMax=floorDiv(b*s-twoB,N);for(let r=rMin;r<=rMax;r++){const lo=bigMax(a,ceilDiv(twoB+r*N,s)),hi=bigMin(b,floorDiv(threeB-1n+r*N,s));if(lo<=hi)newM.push([lo,hi]);}}
    M=newM;
    
    if(M.length===1&&M[0][0]===M[0][1]){
      const ms2=Date.now()-t0;
      const mBytes=toBytes(M[0][0],k);
      let i=2;while(i<mBytes.length&&mBytes[i]!==0)i++;
      const plain=Buffer.from(mBytes.slice(i+1)).toString();
      return{m:M[0][0],total,step,ms:ms2,plain,log};
    }
    if(M.length===1){const[a,b]=M[0];const r=ceilDiv(2n*(b*s-twoB),N);s=ceilDiv(twoB+r*N,b);}
    else s=s+1n;
  }
}

console.log('Generating 96-bit RSA keys (e=3)...');
const{pk,sk}=rsaKeygen3(96);
console.log(`N=${pk.N.toString(16)}, e=${pk.e}`);
console.log(`k=${byteLen(pk.N)} bytes, B=2^${(byteLen(pk.N)-2)*8}`);

const mBytes=Buffer.from('Y');
const{c,em}=pkcs15Enc(pk,mBytes);
console.log(`c=${c.toString(16)}`);
console.log(`em=[${Array.from(em).join(',')}]`);
console.log(`\nRunning Bleichenbacher...`);

const res=bleichenbacher(pk,c,sk);
console.log(`\n✓ "${res.plain}" in ${res.total} queries, ${res.step} steps, ${res.ms}ms`);
console.log('\n=== HARDCODE DATA ===');
console.log(JSON.stringify({N:pk.N.toString(16),e:pk.e.toString(16),d:sk.d.toString(16),p:sk.p.toString(16),q:sk.q.toString(16),c:c.toString(16),em:Array.from(em),plain:res.plain,totalQueries:res.total,steps:res.step,ms:res.ms,log:res.log},null,2));
