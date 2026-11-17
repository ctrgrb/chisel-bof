/* x25519.c - Curve25519 X25519 (RFC 8032) for the chisel SSH client.
 * Field: 4x uint64 LE limbs, reduced mod 2^255-19.
 * Scalar mult mod l: Montgomery form as in x/crypto/curve25519.go. */
#include "chisel_crypto.h"
#include <string.h>
#include <stdint.h>

typedef struct { uint64_t v[4]; } fe;

static void mul128(uint64_t a,uint64_t b,uint64_t *lo,uint64_t *hi){
 uint32_t a0=(uint32_t)a,a1=(uint32_t)(a>>32);
 uint32_t b0=(uint32_t)b,b1=(uint32_t)(b>>32);
 uint64_t p0=(uint64_t)a0*b0,p1=(uint64_t)a0*b1;
 uint64_t p2=(uint64_t)a1*b0,p3=(uint64_t)a1*b1;
 uint64_t mid=(p0>>32)+(p1&0xffffffffull)+(p2&0xffffffffull);
 *lo=(p0&0xffffffffull)|(mid<<32);
 *hi=p3+(p1>>32)+(p2>>32)+(mid>>32);
}
static void add64c(uint64_t *L,int k,uint64_t x){
 uint64_t t=L[k]+x,c=(t<L[k]); L[k]=t;
 while(c && ++k<8){ t=L[k]+1; c=(t<L[k]); L[k]=t; }
}

static void fe_can(fe *c);
/* fold a full 8-limb (512-bit) product mod 2^255-19:
   2^256 = 38, 2^320 = 38*2^64 (mod p) */
static void foldp(const uint64_t L[8],fe *o){
 uint64_t S[8],lo,hi; int i;
 S[0]=L[0];S[1]=L[1];S[2]=L[2];S[3]=L[3];S[4]=0;S[5]=0;S[6]=0;S[7]=0;
 for(i=0;i<4;i++){
  mul128(L[4+i],38ull,&lo,&hi);
  add64c(S,i,lo); add64c(S,i+1,hi);
 }
 for(;;){
  uint64_t q0=S[4],q1=S[5];
  S[4]=0;S[5]=0;
  if(!q0&&!q1) break;
  mul128(q0,38ull,&lo,&hi);
  add64c(S,0,lo); add64c(S,1,hi);
  mul128(q1,38ull,&lo,&hi);
  add64c(S,1,lo); add64c(S,2,hi);
 }
 o->v[0]=S[0];o->v[1]=S[1];o->v[2]=S[2];o->v[3]=S[3];
 fe_can(o); fe_can(o);
}
static void fe_can(fe *c){
 uint64_t *x=c->v;
 if(x[3]&0x8000000000000000ull){
  uint64_t k,t;
  x[3]&=0x7fffffffffffffffull;
  t=x[0]+19ull; k=(t<x[0]); x[0]=t;
  t=x[1]+k; k=(t<x[1]); x[1]=t;
  t=x[2]+k; k=(t<x[2]); x[2]=t;
  x[3]+=k;
 }
 if(x[3]>0x7fffffffffffffffull
 ||(x[3]==0x7fffffffffffffffull&&x[2]==0xffffffffffffffffull
   &&x[1]==0xffffffffffffffffull&&x[0]>=0xffffffffffffffeduLL)){
  uint64_t b,t;
  t=x[0]-0xffffffffffffffeduLL; b=(x[0]<0xffffffffffffffeduLL); x[0]=t;
  uint64_t n=x[1]-0xffffffffffffffffull-b;
  t=(x[1]<0xffffffffffffffffull)||(x[1]==0xffffffffffffffffull&&b); x[1]=n; b=t;
  n=x[2]-0xffffffffffffffffull-b;
  t=(x[2]<0xffffffffffffffffull)||(x[2]==0xffffffffffffffffull&&b); x[2]=n; b=t;
  x[3]-=0x7fffffffffffffffull; x[3]-=b;
 }
 if(x[3]&0x8000000000000000ull){
  uint64_t k,t;
  x[3]&=0x7fffffffffffffffull;
  t=x[0]+19ull; k=(t<x[0]); x[0]=t;
  t=x[1]+k; k=(t<x[1]); x[1]=t;
  t=x[2]+k; k=(t<x[2]); x[2]=t;
  x[3]+=k;
 }
}
static void fe_red(fe *c){
 uint64_t L[8]={c->v[0],c->v[1],c->v[2],c->v[3],0,0,0,0};
 foldp(L,c);
}
static void fe_new(fe *c,uint64_t n){ c->v[0]=n;c->v[1]=0;c->v[2]=0;c->v[3]=0; }
static void fe_copy(fe *d,const fe *c){ d->v[0]=c->v[0];d->v[1]=c->v[1];d->v[2]=c->v[2];d->v[3]=c->v[3]; }
static void fe_add(fe *o,const fe *a,const fe *b){
 uint64_t k=0,t; int i;
 for(i=0;i<4;i++){
  t=a->v[i]+k; uint64_t c1=(t<k); o->v[i]=t;
  uint64_t u=o->v[i]+b->v[i]; uint64_t c2=(u<o->v[i]); o->v[i]=u;
  k=c1+c2;
 }
 fe_red(o);
}
static void fe_sub(fe *o,const fe *a,const fe *b){
 uint64_t br=0,t; int i;
 for(i=0;i<4;i++){
  t=a->v[i]-b->v[i]; uint64_t b1=(a->v[i]<b->v[i]);
  uint64_t t2=t-br; uint64_t b2=(t<br);
  o->v[i]=t2; br=b1+b2;
 }
 if(br){
  uint64_t k=0; (void)br;
  static const uint64_t P[4]={0xffffffffffffffeduLL,0xffffffffffffffffull,
   0xffffffffffffffffull,0x7fffffffffffffffull};
  for(i=0;i<4;i++){
   uint64_t u=o->v[i]+P[i]; uint64_t c2=(u<o->v[i]);
   u+=k; c2+=(u<k); o->v[i]=u; k=c2;
  }
 }
 fe_red(o);
}
static void fe_mul(fe *o,const fe *a,const fe *b){
 uint64_t L[8]={0,0,0,0,0,0,0,0}; int i,j;
 for(i=0;i<4;i++)for(j=0;j<4;j++){
  uint64_t lo,hi; mul128(a->v[i],b->v[j],&lo,&hi);
  add64c(L,i+j,lo); add64c(L,i+j+1,hi);
 }
 foldp(L,o);
}
static void fe_sq(fe *o,const fe *a){ fe_mul(o,a,a); }
static void fe_swap(uint64_t s,fe *x,fe *y){
 uint64_t t=-(s&1ull); int i;
 for(i=0;i<4;i++){ uint64_t k=((*x).v[i]^(*y).v[i])&t; (*x).v[i]^=k; (*y).v[i]^=k; }
}
static void fe_pow(fe *out,const fe *x,const uint8_t *e,int elen){
 fe r; fe_new(&r,1);
 int i,b;
 for(b=elen-1;b>=0;b--)
  for(i=7;i>=0;i--){
   fe_sq(&r,&r);
   if((e[b]>>i)&1) fe_mul(&r,&r,x);
  }
 fe_copy(out,&r);
}
static void fe_invert(fe *out,const fe *x){
 static const uint8_t e[32]={
  0xeb,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f};
 fe_pow(out,x,e,32);
}
static void fe_le(const uint8_t b[32],fe *o){
 int i;
 for(i=0;i<4;i++)
  o->v[i]=(uint64_t)b[i*8]|((uint64_t)b[i*8+1]<<8)|((uint64_t)b[i*8+2]<<16)|
   ((uint64_t)b[i*8+3]<<24)|((uint64_t)b[i*8+4]<<32)|((uint64_t)b[i*8+5]<<40)|
   ((uint64_t)b[i*8+6]<<48)|((uint64_t)b[i*8+7]<<56);
 o->v[3]&=0x7fffffffffffffffull;
 fe_can(o);
}
static void fe_le_out(const fe *x,uint8_t b[32]){
 int i;
 for(i=0;i<32;i++) b[i]=(uint8_t)(x->v[i/8]>>((i%8)*8));
}

static void x25519_core(const uint8_t k[32],const uint8_t u[32],uint8_t out[32]);
void x25519_scalarmul(const uint8_t s[32],const uint8_t u[32],uint8_t out[32]){
 uint8_t k[32]; int i;
 for(i=0;i<32;i++)k[i]=s[i];
 k[0]&=248; k[31]&=127; k[31]|=64;
 x25519_core(k,u,out);
}
void x25519_base(const uint8_t k[32],uint8_t out[32]){
 uint8_t kk[32],u9[32]; int i;
 for(i=0;i<32;i++)kk[i]=k[i];
 kk[0]&=248; kk[31]&=127; kk[31]|=64;
 u9[0]=9; for(i=1;i<32;i++)u9[i]=0;
 x25519_core(kk,u9,out);
}
void x25519_clamp(uint8_t k[32]){ k[0]&=248; k[31]&=127; k[31]|=64; }

/* ---- X25519 ladder (RFC 8032 Algorithm 1) ---- */
static void x25519_core(const uint8_t k[32],const uint8_t u[32],uint8_t out[32]){
 fe x1,x2,x3,z2,z3,t0,t1,tmp,a24,zi;
 int i; uint64_t swap=0; uint8_t ubuf[32];
 for(i=0;i<32;i++) ubuf[i]=u[i];
 ubuf[31]&=0x7f;
 fe_le(ubuf,&x1);
 fe_new(&x2,1); fe_new(&z2,0);
 fe_copy(&x3,&x1); fe_new(&z3,1);
 fe_new(&a24,121666u);
 for(i=254;i>=0;i--){
  int bit=(k[i/8]>>(i&7))&1;
  swap^=(uint64_t)bit;
  fe_swap(swap,&x2,&x3);
  fe_swap(swap,&z2,&z3);
  swap=(uint64_t)bit;
  fe_sub(&t0,&x3,&z3);
  fe_sub(&t1,&x2,&z2);
  fe_add(&x2,&x2,&z2);
  fe_add(&tmp,&x3,&z3);
  fe_mul(&z2,&tmp,&t1);
  fe_mul(&z3,&t0,&x2);
  fe_sq(&t0,&t1);
  fe_sq(&t1,&x2);
  fe_add(&x3,&z3,&z2);
  fe_sub(&tmp,&z3,&z2);
  fe_mul(&x2,&t1,&t0);
  fe_sub(&t1,&t1,&t0);
  fe_sq(&z2,&tmp);
  fe_mul(&z3,&t1,&a24);
  fe_sq(&x3,&x3);
  fe_add(&t0,&t0,&z3);
  fe_mul(&z3,&x1,&z2);
  fe_mul(&z2,&t1,&t0);
 }
 fe_swap(swap,&x2,&x3);
 fe_swap(swap,&z2,&z3);
 fe_invert(&zi,&z2);
 fe_mul(&x2,&x2,&zi);
 fe_le_out(&x2,out);
}
