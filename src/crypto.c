/* crypto.c - SHA-256, SSH KDF, base64, chacha20 (IEEE), poly1305.
 * No platform crypto APIs; matches x/crypto implementations. */
#include "chisel_crypto.h"
#include <string.h>
#include <stdint.h>

/* Freestanding .obj has no CRT: these definitions also satisfy GCC's
   implicit memcpy/memset calls from struct/aggregate copies. */
void *memcpy(void *d,const void *s,size_t n){
 uint8_t *a=(uint8_t*)d; const uint8_t *b=(const uint8_t*)s; size_t i;
 for(i=0;i<n;i++) a[i]=b[i];
 return d;
}
void *memset(void *d,int c,size_t n){
 uint8_t *a=(uint8_t*)d; size_t i;
 for(i=0;i<n;i++) a[i]=(uint8_t)c;
 return d;
}
void *memmove(void *d,const void *s,size_t n){
 uint8_t *a=(uint8_t*)d; const uint8_t *b=(const uint8_t*)s; size_t i;
 if(a==b||n==0) return d;
 if(a<b){ for(i=0;i<n;i++) a[i]=b[i]; }
 else { for(i=n;i>0;i--) a[i-1]=b[i-1]; }
 return d;
}
int memcmp(const void *x,const void *y,size_t n){
 const uint8_t *a=(const uint8_t*)x; const uint8_t *b=(const uint8_t*)y; size_t i;
 for(i=0;i<n;i++) if(a[i]!=b[i]) return (int)a[i]-(int)b[i];
 return 0;
}
size_t strlen(const char *s){ size_t n=0; while(s[n]) n++; return n; }
int strcmp(const char *x,const char *y){
 while(*x&&*y&&*x==*y){ x++; y++; }
 return (int)(unsigned char)*x-(int)(unsigned char)*y;
}
char *strstr(const char *h,const char *n){
 size_t nl=strlen(n); const char *p;
 if(!nl) return (char*)h;
 for(p=h;*p;p++) if(*p==*n && memcmp(p,n,nl)==0) return (char*)p;
 return 0;
}
char *strchr(const char *s,int c){
 for(;*s;s++) if(*s==(char)c) return (char*)s;
 return 0;
}
/* MBED.a debug path references stdio; no CRT in the payload. */
int printf(const char *fmt, ...){ (void)fmt; return 0; }
int putchar(int c){ (void)c; return c; }
int puts(const char *s){ (void)s; return 1; }

void sha256_copy(sha256 *src,sha256 *dst){
dst->state[0]=src->state[0];dst->state[1]=src->state[1];
dst->state[2]=src->state[2];dst->state[3]=src->state[3];
dst->state[4]=src->state[4];dst->state[5]=src->state[5];
dst->state[6]=src->state[6];dst->state[7]=src->state[7];
dst->len=src->len; dst->off=src->off;
memcpy(dst->buf,src->buf,64);
}

static const uint32_t sha_k[64] = {
	0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
	0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
	0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
	0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
	0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
	0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
	0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
	0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
static uint32_t ror32(uint32_t x,int n){return (x>>n)|(x<<(32-n));}

void sha256_init(sha256 *h){
	h->state[0]=0x6a09e667u;h->state[1]=0xbb67ae85u;h->state[2]=0x3c6ef372u;h->state[3]=0xa54ff53au;
	h->state[4]=0x510e527fu;h->state[5]=0x9b05688cu;h->state[6]=0x1f83d9abu;h->state[7]=0x5be0cd19u;
	h->len=0; h->off=0;
}
static void sha256_block(sha256 *h,const uint8_t *b){
	uint32_t w[64],a,b2,c,d,e,f,g,hh; int i;
	for(i=0;i<16;i++)
	 w[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|b[i*4+3];
	for(i=16;i<64;i++){
	 uint32_t s0=ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3);
	 uint32_t s1=ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10);
	 w[i]=w[i-16]+s0+w[i-7]+s1;
	}
	 a=h->state[0];b2=h->state[1];c=h->state[2];d=h->state[3];
	e=h->state[4];f=h->state[5];g=h->state[6];hh=h->state[7];
	for(i=0;i<64;i++){
	 uint32_t S1=ror32(e,6)^ror32(e,11)^ror32(e,25);
	 uint32_t ch=(e&f)^(~e&g);
	 uint32_t T1=hh+S1+ch+sha_k[i]+w[i];
	 uint32_t S0=ror32(a,2)^ror32(a,13)^ror32(a,22);
	 uint32_t maj=(a&b2)^(a&c)^(b2&c);
	 uint32_t T2=S0+maj;
	 hh=g;g=f;f=e;e=d+T1;d=c;c=b2;b2=a;a=T1+T2;
	}
	h->state[0]+=a;h->state[1]+=b2;h->state[2]+=c;h->state[3]+=d;
	h->state[4]+=e;h->state[5]+=f;h->state[6]+=g;h->state[7]+=hh;
}
void sha256_update(sha256 *h,const void *p,size_t n){
	const uint8_t *b=(const uint8_t*)p;
	h->len+=n;
	 while(n){
	 size_t take=64-h->off;
	 if(take>n) take=n;
	 memcpy(&h->buf[h->off],b,take);
	 h->off+=take; b+=take; n-=take;
	 if(h->off==64){ sha256_block(h,h->buf); h->off=0; }
	 }
}
void sha256_final(sha256 *h,uint8_t out[32]){
	sha256 h2; sha256_copy(h,&h2);
	{ uint8_t pad=0x80u; (void)pad; }
	sha256_update(&h2,"\x80",1);
	while(h2.off!=56) sha256_update(&h2,"\0",1);
	{ uint8_t lb[8]; uint64_t bits=(uint64_t)h->len*8u; int i;
	  for(i=0;i<8;i++) lb[i]=(uint8_t)(bits>>(56-8*i));
	  sha256_update(&h2,lb,8);
	 }
	{ int i; for(i=0;i<8;i++){
	 out[i*4]=(uint8_t)(h2.state[i]>>24);
	 out[i*4+1]=(uint8_t)(h2.state[i]>>16);
	 out[i*4+2]=(uint8_t)(h2.state[i]>>8);
	 out[i*4+3]=(uint8_t)h2.state[i];
	 } }
}
void sha256_hash(const void *p,size_t n,uint8_t out[32]){
	sha256 h; sha256_init(&h); sha256_update(&h,p,n); sha256_final(&h,out);
}
void ssh_kdf(uint8_t *out,size_t n,const uint8_t *K,size_t Klen,
	const uint8_t *H32,const uint8_t *sessionId,size_t sidlen,uint8_t tag)
{
	sha256 h; uint8_t all[256]; size_t dn=0,got=0;
	while(got<n){
	 sha256_init(&h);
	 sha256_update(&h,K,Klen);
	 sha256_update(&h,H32,32);
	if(dn==0){ sha256_update(&h,&tag,1); sha256_update(&h,sessionId,sidlen); }
	 else sha256_update(&h,all,dn);
	 uint8_t dig[32];
	 sha256_final(&h,dig);
	 size_t take=n-got; if(take>32) take=32;
	 memcpy(out+got,dig,take);
	 got+=take;
	 if(got<n){ memcpy(all+dn,dig,32); dn+=32; }
	}
	(void)dn;
}

void chacha20_keystream(const uint8_t key[32],const uint8_t nonce[12],
	 uint32_t ctr,uint8_t *out,size_t n)
{
	/* RFC 8439 ChaCha20: words 0-3 constants, 4-11 key LE,
	   word 12 counter LE, words 13-15 nonce LE. */
 uint32_t st[16]; size_t i; uint8_t ks[64];
	 st[0]=0x61707865u; st[1]=0x3320646eu; st[2]=0x79622d32u; st[3]=0x6b206574u;
	for(i=0;i<8;i++)
	 st[4+i]=(uint32_t)key[i*4]|((uint32_t)key[i*4+1]<<8)|
	 ((uint32_t)key[i*4+2]<<16)|((uint32_t)key[i*4+3]<<24);
	for(i=0;i<3;i++)
	 st[13+i]=(uint32_t)nonce[i*4]|((uint32_t)nonce[i*4+1]<<8)|
	 ((uint32_t)nonce[i*4+2]<<16)|((uint32_t)nonce[i*4+3]<<24);
	 st[12]=0u;
#define ROTL(a,n) ((a)<<(n)|(a)>>(32-(n)))
#define QR(a,b,c,d) st[a]+=st[b];st[d]^=st[a];st[d]=ROTL(st[d],16);\
	 st[c]+=st[d];st[b]^=st[c];st[b]=ROTL(st[b],12);\
	 st[a]+=st[b];st[d]^=st[a];st[d]=ROTL(st[d],8);\
	 st[c]+=st[d];st[b]^=st[c];st[b]=ROTL(st[b],7);
	 size_t off=0;
	while(off<n){
	 uint32_t s[16]; int r,j;
	 for(j=0;j<16;j++) s[j]=st[j];
	 s[12]=ctr++;
	 for(r=0;r<10;r++){
	 /* column round */
	 { uint32_t *x=s;
	 x[0]+=x[4];x[12]^=x[0];x[12]=ROTL(x[12],16);x[8]+=x[12];x[4]^=x[8];x[4]=ROTL(x[4],12);
	  x[0]+=x[4];x[12]^=x[0];x[12]=ROTL(x[12],8);x[8]+=x[12];x[4]^=x[8];x[4]=ROTL(x[4],7);
	 x[1]+=x[5];x[13]^=x[1];x[13]=ROTL(x[13],16);x[9]+=x[13];x[5]^=x[9];x[5]=ROTL(x[5],12);
	  x[1]+=x[5];x[13]^=x[1];x[13]=ROTL(x[13],8);x[9]+=x[13];x[5]^=x[9];x[5]=ROTL(x[5],7);
	 x[2]+=x[6];x[14]^=x[2];x[14]=ROTL(x[14],16);x[10]+=x[14];x[6]^=x[10];x[6]=ROTL(x[6],12);
	  x[2]+=x[6];x[14]^=x[2];x[14]=ROTL(x[14],8);x[10]+=x[14];x[6]^=x[10];x[6]=ROTL(x[6],7);
	 x[3]+=x[7];x[15]^=x[3];x[15]=ROTL(x[15],16);x[11]+=x[15];x[7]^=x[11];x[7]=ROTL(x[7],12);
	  x[3]+=x[7];x[15]^=x[3];x[15]=ROTL(x[15],8);x[11]+=x[15];x[7]^=x[11];x[7]=ROTL(x[7],7);
	 /* diagonal round */
	 x[0]+=x[5];x[15]^=x[0];x[15]=ROTL(x[15],16);x[10]+=x[15];x[5]^=x[10];x[5]=ROTL(x[5],12);
	  x[0]+=x[5];x[15]^=x[0];x[15]=ROTL(x[15],8);x[10]+=x[15];x[5]^=x[10];x[5]=ROTL(x[5],7);
	 x[1]+=x[6];x[12]^=x[1];x[12]=ROTL(x[12],16);x[11]+=x[12];x[6]^=x[11];x[6]=ROTL(x[6],12);
	  x[1]+=x[6];x[12]^=x[1];x[12]=ROTL(x[12],8);x[11]+=x[12];x[6]^=x[11];x[6]=ROTL(x[6],7);
	 x[2]+=x[7];x[13]^=x[2];x[13]=ROTL(x[13],16);x[8]+=x[13];x[7]^=x[8];x[7]=ROTL(x[7],12);
	  x[2]+=x[7];x[13]^=x[2];x[13]=ROTL(x[13],8);x[8]+=x[13];x[7]^=x[8];x[7]=ROTL(x[7],7);
	 x[3]+=x[4];x[14]^=x[3];x[14]=ROTL(x[14],16);x[9]+=x[14];x[4]^=x[9];x[4]=ROTL(x[4],12);
	  x[3]+=x[4];x[14]^=x[3];x[14]=ROTL(x[14],8);x[9]+=x[14];x[4]^=x[9];x[4]=ROTL(x[4],7);
	 }
	 }
	 for(j=0;j<16;j++){
	 uint32_t v=s[j]+st[j];
	 ks[j*4]=(uint8_t)v; ks[j*4+1]=(uint8_t)(v>>8);
	 ks[j*4+2]=(uint8_t)(v>>16); ks[j*4+3]=(uint8_t)(v>>24);
	 }
	 size_t take=n-off; if(take>64) take=64;
	 memcpy(out+off,ks,take);
	 off+=64;
	}
	(void)i;
#undef QR
#undef ROTL
}

/* ================= Poly1305 (clamped r/s, mod 2^130-5) ================= */
static uint64_t le64(const uint8_t *b){
	uint64_t v=0; int i; for(i=7;i>=0;i--) v=(v<<8)|b[i]; return v;
}
static void st64(uint8_t *b,uint64_t v){ int i; for(i=0;i<8;i++) b[i]=(uint8_t)(v>>(8*i)); }
static uint64_t adc(uint64_t a,uint64_t b,uint64_t ci,uint64_t *co){
uint64_t r=a+b; uint64_t c1=(r<a); uint64_t r2=r+ci; uint64_t c2=(r2<r);
*co=c1|c2; return r2;
}
static uint64_t sbb(uint64_t a,uint64_t b,uint64_t bi,uint64_t *bo){
uint64_t r=a-b; uint64_t b1=(a<b); uint64_t r2=r-bi; uint64_t b2=(r<bi);
*bo=b1|b2; return r2;
}
static void hmulr(uint64_t *h,uint64_t r0,uint64_t r1){
__uint128_t m0=(__uint128_t)h[0]*r0;
__uint128_t m1=(__uint128_t)h[1]*r0+(__uint128_t)h[0]*r1;
__uint128_t m2=(__uint128_t)h[2]*r0+(__uint128_t)h[1]*r1;
__uint128_t m3=(__uint128_t)h[2]*r1;
uint64_t cc,t0,t1,t2,t3;
t0=(uint64_t)m0;
t1=adc((uint64_t)m1,(uint64_t)(m0>>64),0,&cc);
t2=adc((uint64_t)m2,(uint64_t)(m1>>64),cc,&cc);
t3=adc((uint64_t)m3,(uint64_t)(m2>>64),cc,&cc);
{
uint64_t h0=t0,h1=t1,h2=t2&3ull;
uint64_t c0=t2&~3ull,c1=t3;
h0=adc(h0,c0,0,&cc); h1=adc(h1,c1,cc,&cc); h2+=cc;
c0=(c0>>2)|(c1<<62); c1>>=2;
h0=adc(h0,c0,0,&cc); h1=adc(h1,c1,cc,&cc); h2+=cc;
h[0]=h0; h[1]=h1; h[2]=h2;
}
}

void poly1305_sum(uint8_t out[16],const uint8_t *msg,size_t n,const uint8_t key[32]){
uint64_t h[3]; h[0]=h[1]=h[2]=0;
uint64_t r0=le64(key)&0x0FFFFFFC0FFFFFFFull;
uint64_t r1=le64(key+8)&0x0FFFFFFC0FFFFFFCull;
uint64_t s0=le64(key+16),s1=le64(key+24);
size_t off=0; uint64_t cc;
while(n-off>=16){
uint64_t c0=le64(msg+off),c1=le64(msg+off+8);
h[0]=adc(h[0],c0,0,&cc);
h[1]=adc(h[1],c1,cc,&cc);
h[2]+=cc+1;
hmulr(h,r0,r1);
off+=16;
}
if(n>off){
uint8_t buf[16]; size_t rem=n-off;
memcpy(buf,msg+off,rem); memset(buf+rem,0,16-rem); buf[rem]=1;
h[0]=adc(h[0],le64(buf),0,&cc);
h[1]=adc(h[1],le64(buf+8),cc,&cc);
h[2]+=cc;
hmulr(h,r0,r1);
}
{
uint64_t b,hp0,hp1,d;
hp0=sbb(h[0],0xFFFFFFFFFFFFFFFBull,0,&b);
hp1=sbb(h[1],0xFFFFFFFFFFFFFFFFull,b,&b);
(void)sbb(h[2],3ull,b,&d); b=d;
if(!b){ h[0]=hp0; h[1]=hp1; }
h[0]=adc(h[0],s0,0,&cc); h[1]=adc(h[1],s1,cc,&cc);
st64(out,h[0]); st64(out+8,h[1]);
}
}

static const char b64tab[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64_encode(const uint8_t *in,int n,char *out){
int i=0,o=0;
while(n-i>=3){
uint32_t v=((uint32_t)in[i]<<16)|((uint32_t)in[i+1]<<8)|in[i+2];
out[o++]=b64tab[(v>>18)&63];out[o++]=b64tab[(v>>12)&63];
out[o++]=b64tab[(v>>6)&63];out[o++]=b64tab[v&63];
i+=3;
}
if(n-i==1){
uint32_t v=(uint32_t)in[i]<<16;
out[o++]=b64tab[(v>>18)&63];out[o++]=b64tab[(v>>12)&63];
out[o++]='=';out[o++]='=';
} else if(n-i==2){
uint32_t v=((uint32_t)in[i]<<16)|((uint32_t)in[i+1]<<8);
out[o++]=b64tab[(v>>18)&63];out[o++]=b64tab[(v>>12)&63];
out[o++]=b64tab[(v>>6)&63];out[o++]='=';
}
out[o]=0;
return o;
}

size_t mpint_payload(const uint8_t *sec,size_t n,uint8_t *out){
size_t i=0;
while(i<n-1 && sec[i]==0) i++;
uint8_t pad=(sec[i]&0x80)?1:0;
size_t len=n-i+pad;
out[0]=(uint8_t)(len>>24);out[1]=(uint8_t)(len>>16);
out[2]=(uint8_t)(len>>8);out[3]=(uint8_t)len;
if(pad) out[4]=0;
memcpy(out+4+pad,sec+i,n-i);
return 4+len;
}
