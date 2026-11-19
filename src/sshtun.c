/* tools/ext/sshtun.c — chisel-v3 SSH-over-WS + SOCKS5-over-channel glue.
 * Shared verbatim by tools/ext/tlsprobe.c (console twin) and bof/stock.c
 * The includer MUST, BEFORE this #include, define ws_put(ctx,pl,pn) /
 *   ws_get(ctx,pl,&pn,maxpl) (one WS binary frame each over the TLS record
 *   layer) and sock_connect(host,port) (dial a target, blocking fd or -1).
 * plus externs: b64_encode, sha256_*, ssh_kdf, chacha20_keystream,
 * poly1305_sum, mpint_payload, x25519_*, winsock BSD send/recv/closesocket.
 *
 * Wire truth (golang.org/x/crypto/ssh v0.55.0, vendored as Go sources here):
 * one WS binary message per SSH wire packet; the version line is its own
 * frame; packets are cleartext (u32 len || pad || payload || pad) until each
 * side writes msgNewKeys(21), then chacha20-poly1305 with the sequence
 * number CONTINUING (non-strict KEX); curve25519-sha256 KEX only (never
 * advertise mlkem768x25519-sha256 or ext-info-c); KDF tags 'C' (our writes)
 * / 'D' (our reads) over the marshalled mpint K (u32 length prefix INCLUDED).
 */
#ifdef DIAG_MARK
char stock_log[4194304];
static size_t dlp;
extern unsigned long long GetTickCount64(void);
static void slogw(const char *f,...)
{
  const char *p=f; char *o=stock_log; size_t i=dlp;
  { unsigned long long t=GetTickCount64(); char tb[16]; int k=0;
    if(!t)tb[k++]='0'; else while(t){ tb[k++]=(char)('0'+(t%10)); t/=10; }
    while(k) o[i++]=tb[--k]; o[i++]=' '; }
  #include <stdarg.h>
  { va_list ap; va_start(ap,f);
    while(p&&*p){
      if(*p!='%'){ o[i++]=*p++; if(i>=sizeof stock_log-1)break; p=p; continue; }
      p++;
      if(*p=='d'||*p=='u'){ int isum=0; unsigned vu; const char *nb; char tmp[16]; int k=0;
        if(*p=='d'){ isum=va_arg(ap,int); if(isum<0){ o[i++]='-'; vu=(unsigned)(-isum);} else vu=(unsigned)isum; }
        else { vu=va_arg(ap,unsigned int); }
        p++;
        if(!vu){ o[i++]='0'; }
        else { while(vu){ tmp[k++]=(char)('0'+(vu%10u)); vu/=10u; } while(k) o[i++]=tmp[--k]; }
      }
      else if(*p=='s'){ const char *s=va_arg(ap,const char*); p++; if(!s){ s="(null)"; } while(*s){ o[i++]=*s++; if(i>=sizeof stock_log-1)break; } }
      else { o[i++]=*p++; }
      if(i>=sizeof stock_log-1){ i=dlp=0; }
    }
    va_end(ap);
  }
  o[i++]=0; if(i>=sizeof stock_log-1)i=0; dlp=i;
}
#define SLOG(...) slogw(__VA_ARGS__)
#ifdef DIAG_MARK
extern unsigned long long GetTickCount64(void);
static int sl_close(int fd){ SLOG("close fd=%d u=%u",fd,(unsigned)GetTickCount64());
#undef closesocket
  { int r=closesocket(fd);
#define closesocket(x) sl_close(x)
    return r; } }
#define closesocket(x) sl_close(x)
static int sl_shut(int fd,int how){ SLOG("shut fd=%d how=%d u=%u",fd,how,(unsigned)GetTickCount64());
#undef shutdown
  { int r=shutdown(fd,how);
#define shutdown(x,y) sl_shut(x,y)
    return r; } }
#define shutdown(x,y) sl_shut(x,y)
#endif
#else
#ifndef SLOG
#if defined(TWIN_MAIN)
/* Console twin: the wire-layer marks go to stderr as well as the OUT() lines. The
 * keepalive, per-phase timeout and auth diagnostics live in this file, so without them
 * the twin can only show the outer loop's messages.  Format strings here are the same
 * subset slogw() understands (%d, %u, %s - never %llu). */
#define SLOG(...) do{ fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); }while(0)
#else
#define SLOG(...) ((void)0)
#endif
#endif
#endif

#include <stdint.h>
#include <stddef.h>
#include "chisel_crypto.h"

extern int WSAGetLastError(void);
extern int send(int, const char *, int, int);
extern int recv(int, char *, int, int);
extern int closesocket(int);
extern int shutdown(int, int);
/* host-file contract (stock.c, defined above this include):
 *   now_ms() -> monotonic ms (GetTickCount64)
 *   sock_timeo(sd, ms) -> SO_RCVTIMEO/SO_SNDTIMEO; ms==0 clears both
 *   ss_set_ka is implemented HERE and called by the host file  */
extern int ws_put(void *, const unsigned char *, int);
extern int ws_get(void *, unsigned char *, int *, int);
extern int sock_connect(const char *, int);   /* target dials: native winsock fd, BLOCKING (the
    dial itself is the only non-blocking phase); writes are select()-gated and abandon a wedged
    channel after the ~30 s write deadline - see docs/stability-invariants.md */
extern int sock_udp_dial(const char *, int);  /* connected UDP target socket (winsock1 proto 4) */
extern int tls_buffered(void *);              /* 1 = mbedtls input buffer already holds readable bytes */
extern void ws_set_nb(void);                  /* enable post-handshake non-blocking outbox sends */
extern int ws_outbox_pending(void);           /* 1 = a WS frame is queued awaiting writability */
extern int ws_outbox_flush(void *);           /* try to drain the outbox: 0 done, 1 pending, -1 error */
int tls_fd=-1;                              /* underlying TLS socket fd, set by ss_run */
#ifndef FD_SET1_DEF
#define FD_SET1_DEF
typedef struct { unsigned int fd_count; unsigned long long fd_array[64]; } fd_set1;
typedef struct { long sec; long usec; } tv1;
#endif
#ifdef DIAG_MARK
#ifndef DMHOST
#define DMHOST "127.0.0.1"
#endif
/* DM phase markers retired: each failed dm() connect cost ~2s SYN retry and
 * poisoned every DIAG timing run. Kept as no-ops; the ship build never had them. */
#define DM(x) ((void)0)
#else
#define DM(x)
#endif


/* diagnostic hex dump (chunked) */
static void sdump(const char *tag,const uint8_t *b,size_t n)
{
	const char *hx="0123456789abcdef"; size_t o=0,i,m; char buf[66];
	for(; o<n; o+=m){
		m=n-o; if(m>32) m=32;
		{ for(i=0;i<m;i++){ buf[i*2]=hx[(b[o+i]>>4)&15]; buf[i*2+1]=hx[b[o+i]&15]; } }
		buf[m*2]=0;
		SLOG("D %s %u/%u %s",tag,(unsigned)o,(unsigned)n,buf);
	}
}

/* prng: fixed seed (the bare DLL has no NT-kernel entropy import) */
static uint64_t tsd = 0x9E3779B97F4A7C15ull;
static int trndb(void){ tsd ^= tsd<<13; tsd ^= tsd>>7; tsd ^= tsd<<17; return (int)((tsd>>24)&0xff); }

static uint32_t tbe32(const uint8_t *b){ return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|(uint32_t)b[3]; }
static void tput32(uint8_t *b,uint32_t v){ b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16); b[2]=(uint8_t)(v>>8); b[3]=(uint8_t)v; }
static void tcpy(void *d,const void *s,size_t n){ size_t i; uint8_t *a=(uint8_t*)d; const uint8_t *b=(const uint8_t*)s; for(i=0;i<n;i++) a[i]=b[i]; }
static int teq(const char *a,const char *b){ for(;;a++,b++){ if(*a!=*b) return 0; if(!*a) return 1; } }
static int teqp(const char *a,const char *b,size_t nb){ size_t i; for(i=0;i<nb;i++) if(a[i]!=b[i]) return 0; return 1; }

/* ---- packet builder ---- */
#define PB_N 70000
static uint8_t pb[PB_N];
static size_t pn;

static void w_u8(uint8_t v){ if(pn<PB_N) pb[pn++]=v; }
static void w_u32(uint32_t v){ if(pn+4<=PB_N){ pb[pn++]=(uint8_t)(v>>24); pb[pn++]=(uint8_t)(v>>16); pb[pn++]=(uint8_t)(v>>8); pb[pn++]=(uint8_t)v; } }
static void w_bool(int v){ w_u8((uint8_t)(v?1:0)); }
static void w_raw(const void *p,size_t n){ if(pn+n<=PB_N){ tcpy(pb+pn,p,n); pn+=n; } }
static void w_bytes(const void *p,size_t n){ w_u32((uint32_t)n); w_raw(p,n); }
static void w_str(const char *s){ size_t n=0; const char *p=s; while(*p){ n++; p++; } w_bytes(s,n); }
static void w_nlist(const char *const *l,int cnt){
	char j[2048]; size_t n=0,i;
	for(i=0;i<(size_t)cnt;i++){
		const char *s=l[i];
		if(n && n<sizeof j) j[n++]=',';
		{ while(*s && n<sizeof j){ j[n++]=*s; s++; } }
	}
	w_bytes(j,n);
}

/* ---- handshake-hash accumulator ---- */
#define WB_N 330000
static uint8_t wb[WB_N];
static size_t wn;
static void wb_reset(void){ wn=0; }
static void wb_raw(const void *p,size_t n){ if(wn+n<=WB_N){ tcpy(wb+wn,p,n); wn+=n; } else wn=WB_N; }
static void wb_str(const void *p,size_t n){ uint8_t l[4]; tput32(l,(uint32_t)n); wb_raw(l,4); wb_raw(p,n); }

/* ---- received packet ---- */
static uint8_t rpl[WB_N];
static size_t rn;
static size_t rp;

/* ---- WS frame -> byte stream cache ---- */
static uint8_t sbuf[WB_N];
static size_t so,sn;

/* ---- transport state ---- */
static uint8_t key_w[64],key_r[64];
static int st_w,st_r;
static uint32_t seq_w,seq_r;
static uint8_t wirebuf[WB_N];

static void mk_nonce(uint8_t nonce[12],uint32_t seq){ int i; for(i=0;i<8;i++) nonce[i]=0; tput32(nonce+8,seq); }
static int sb_pull(void *ctx,size_t n);

/* Poly1305 one-time MAC: port of the generic Go implementation
 * (h = (h + chunk) * r mod 2^130-5 per 16-byte chunk, last short chunk
 *  terminated by a 0x01 byte; tag = (h + s) little-endian). */
static uint64_t p1305le(const uint8_t *p)
{ uint64_t v=0; int b; for(b=7;b>=0;b--) v=(v<<8)|p[b]; return v; }
static void p1305(uint8_t *out,const uint8_t *msg,size_t n,const uint8_t *key)
{
	const uint64_t M0=0x0FFFFFFC0FFFFFFFull, M1=0x0FFFFFFC0FFFFFFCl;
	const uint64_t P0=0xFFFFFFFFFFFFFFFBl, P1=0xFFFFFFFFFFFFFFFFull;
	#define L2 3ull
	uint64_t r0=p1305le(key)&M0,r1=p1305le(key+8)&M1,s0=p1305le(key+16),s1=p1305le(key+24);
	uint64_t h0=0,h1=0,h2=0,m0,m1,c,i;
	{ unsigned char buf[16];
	  while(n){
	 if(n>=16){ m0=p1305le(msg); m1=p1305le(msg+8); h2+=1; msg+=16; n-=16; }
	 else { for(i=0;i<16;i++) buf[i]=0;
	   for(i=0;i<n;i++) buf[i]=msg[i];
	   buf[n]=1;
	   m0=p1305le(buf); m1=p1305le(buf+8); n=0; }
	 { unsigned __int128 s=(unsigned __int128)h0+m0;
	   h0=(uint64_t)s; c=(uint64_t)(s>>64);
	   s=(unsigned __int128)h1+m1+c; h1=(uint64_t)s; c=(uint64_t)(s>>64);
	   h2+=c; }
	 { unsigned __int128 q0=(unsigned __int128)h0*r0,q1=(unsigned __int128)h1*r0+(unsigned __int128)h0*r1,q2=(unsigned __int128)h2*r0+(unsigned __int128)h1*r1,q3=(unsigned __int128)h2*r1;
	   uint64_t t0,t1,t2,t3; unsigned __int128 s;
	   t0=(uint64_t)q0;
	   s=(unsigned __int128)(uint64_t)(q0>>64)+(uint64_t)q1; t1=(uint64_t)s; c=(uint64_t)(s>>64);
	   s=(unsigned __int128)(uint64_t)(q1>>64)+(uint64_t)q2+c; t2=(uint64_t)s; c=(uint64_t)(s>>64);
	   s=(unsigned __int128)(uint64_t)(q2>>64)+(uint64_t)q3+c; t3=(uint64_t)s;
	   h0=t0; h1=t1; h2=t2&L2;
	 { unsigned __int128 cc=((unsigned __int128)t3<<64)|(t2&~L2),s2;
	   s=(unsigned __int128)h0+(uint64_t)cc;
	   s2=(unsigned __int128)h1+(uint64_t)(cc>>64)+(uint64_t)(s>>64);
	   h1=(uint64_t)s2; h2+=(uint64_t)(s2>>64); h0=(uint64_t)s;
	   cc>>=2;
	   s=(unsigned __int128)h0+(uint64_t)cc;
	   s2=(unsigned __int128)h1+(uint64_t)(cc>>64)+(uint64_t)(s>>64);
	   h1=(uint64_t)s2; h2+=(uint64_t)(s2>>64); h0=(uint64_t)s; }
	 }
	  }
	}
	/* complete the modular reduction: h = h - p iff h >= p (p = [P0,P1,3]) */
	{ uint64_t t0=h0-P0;
	  uint64_t b0=(h0<P0)?1:0;
	  uint64_t t1=h1-P1-b0;
	  uint64_t b1=(b0||h1<P1)?1:0;
	  if(h2>=3+b1){ h0=t0; h1=t1; }
	}
	{ unsigned __int128 s=(unsigned __int128)h0+s0;
	  h0=(uint64_t)s;
	  s=(unsigned __int128)h1+s1+(uint64_t)(s>>64); h1=(uint64_t)s; }
	{ int b; for(b=0;b<8;b++){ out[b]=(uint8_t)h0; h0>>=8; }
	  for(b=0;b<8;b++){ out[8+b]=(uint8_t)h1; h1>>=8; } }
}

static void xch_xor(const uint8_t *key,const uint8_t *nonce,uint32_t ctr,uint8_t *buf,size_t n);
static void ch20_gen(const uint8_t *key,const uint8_t *nonce,uint32_t ctr,uint8_t *out,size_t n);

/* ws_raw_put's codes: -1 transport error, 0 frame written, 1 frame COMMITTED to
   the outbox (partially written - those bytes are on their way exactly once),
   2 refused (the outbox still holds the previous frame - nothing went out). */
static int pk_send_nb(void *ctx)
{
	if(ws_outbox_pending()) return 2;   /* refused: previous frame still draining; caller retries */
	uint8_t nonce[12],ks[64],polyKey[32],tag[16];
	size_t n,pad,clen,i;
	n=pn;
  { static unsigned tx94=0; if((int)pb[0]!=94 || (tx94++&1023u)==0) SLOG("tx t=%d id=%u n=%d",(int)pb[0],(pb[0]>=90?(unsigned)tbe32(pb+1):0u),(int)n); }
	/* stream-cipher padding: multiple of 8, at least 4 (x/crypto cipher.go) */
	pad=8-(1+n)%8;
	if(pad<4) pad+=8;
	clen=1+n+pad;
	tput32(wirebuf,(uint32_t)clen);
	wirebuf[4]=(uint8_t)pad;
	tcpy(wirebuf+5,pb,n);
	for(i=0;i<pad;i++) wirebuf[5+n+i]=(uint8_t)trndb();
	if(!st_w){
		int w=ws_put(ctx,wirebuf,(int)(4+clen)); if(w<0){ SLOG("pk_send wsput fail e=%d",WSAGetLastError()); return -1; }
		{ seq_w++; return w; }
	}
	mk_nonce(nonce,seq_w);
	/* length prefix: separate keystream, lengthKey = key_w[32:64], counter 0 */
	ch20_gen(key_w+32,nonce,0,ks,4);
	for(i=0;i<4;i++) wirebuf[i]^=ks[i];
	/* polyKey: first 32 bytes of the content keystream (counter 0) */
	ch20_gen(key_w,nonce,0,ks,32);
	for(i=0;i<32;i++) polyKey[i]=ks[i];
	/* content resumes at counter 1 (x/crypto consumed 64 keystream bytes:
	   polyKey = ks[0:32], 32 bytes discarded) */
	xch_xor(key_w,nonce,1,wirebuf+4,clen);
	p1305(tag,wirebuf,4+clen,polyKey);
	for(i=0;i<16;i++) wirebuf[4+clen+i]=tag[i];
	{ int w=ws_put(ctx,wirebuf,(int)(4+clen+16)); if(w<0){ SLOG("pk_send wsput fail e=%d",WSAGetLastError()); return -1; }
	  seq_w++; return w; }
}

/* Control/data send: first drain any queued outbox frame (bounded), then send.
   The outbox holds at most one WS frame and the server's readLoop drains our
   writes eagerly, so this returns in ~ms; it is what lets a small control
   packet (pong/93/96/97) overtake a big parked t=94 without a blocking send()
   ever holding the pump away from select(). */
static int pk_send(void *ctx)
{
	int tries=0;
	while(ws_outbox_pending()){
		int f=ws_outbox_flush(ctx); if(f<0) return -1;
		if(f>0){
			if(++tries>2500) return -1;   /* ~5 s of unwritable socket: the transport is dead */
			fd_set1 ws; tv1 tv; ws.fd_count=1; ws.fd_array[0]=(unsigned long long)tls_fd; tv.sec=0; tv.usec=2000; select(0,0,&ws,0,(void*)&tv);
		}
	}
	/* The outbox is free here, so ws_raw_put cannot refuse: 0 and 1 both mean the
	   frame is committed.  The old `tries<400` bound fell out of the loop and then
	   mapped a REFUSED send to success, i.e. it silently dropped control packets
	   (pong / 93 window adjust / 96 eof / 97 close) on a stalled socket - losing a
	   93 also starves the peer's window. */
	{ int r=pk_send_nb(ctx); return (r==0||r==1)?0:-1; }
}

/* ChaCha20 keystream (RFC 8439: consts || key LE || counter || nonce LE).
 * The output feed-backs the INITIAL state, so the counter word contributes
 * to output bytes 48..51 of every block; x/crypto's Cipher.SetCounter +
 * XORKeyStream does the same, one block per 64 bytes. */
static void ch20_gen(const uint8_t *key,const uint8_t *nonce,uint32_t ctr,uint8_t *out,size_t n)
{
	#define C32(p) ((uint32_t)(p)[0]|((uint32_t)(p)[1]<<8)|((uint32_t)(p)[2]<<16)|((uint32_t)(p)[3]<<24))
	#define RL(v,s) (((uint32_t)(v)<<(s))|((uint32_t)(v)>>(32-(s))))
	#define QR(a,b,c_,d) x[(a)]+=x[(b)];x[(d)]^=x[(a)];x[(d)]=RL(x[(d)],16);\
	  x[(c_)]+=x[(d)];x[(b)]^=x[(c_)];x[(b)]=RL(x[(b)],12);\
	  x[(a)]+=x[(b)];x[(d)]^=x[(a)];x[(d)]=RL(x[(d)],8);\
	  x[(c_)]+=x[(d)];x[(b)]^=x[(c_)];x[(b)]=RL(x[(b)],7)
	uint32_t q[16],x[16]; size_t off=0,take,k; uint32_t c=ctr; int j,r;
	q[0]=0x61707865u; q[1]=0x3320646eu; q[2]=0x79622d32u; q[3]=0x6b206574u;
	for(j=0;j<8;j++) q[4+j]=C32(key+4*j);
	for(j=0;j<3;j++) q[13+j]=C32(nonce+4*j);
	while(off<n){
	  q[12]=c++;
	  for(j=0;j<16;j++) x[j]=q[j];
	  for(r=0;r<10;r++){
	 QR(0,4,8,12); QR(1,5,9,13); QR(2,6,10,14); QR(3,7,11,15);
	 QR(0,5,10,15); QR(1,6,11,12); QR(2,7,8,13); QR(3,4,9,14);
	  }
	  take=n-off; if(take>64) take=64;
	  for(j=0;j<16;j++){
	 uint32_t v=x[j]+q[j];
	 for(k=0;k<4;k++) if(off+4*j+k<off+take) out[off+4*j+k]=(uint8_t)(v>>(8*k));
	  }
	  off+=take;
	}
	#undef C32
	#undef RL
	#undef QR
}
/* XOR the keystream into buf; counter advances one block per 64 bytes */
static void xch_xor(const uint8_t *key,const uint8_t *nonce,uint32_t ctr,uint8_t *buf,size_t n)
{
	uint8_t ks[64];
	size_t off=0,take,i;
	while(n){
	  take=n; if(take>64) take=64;
	  ch20_gen(key,nonce,ctr,ks,take);
	  for(i=0;i<take;i++) buf[off+i]^=ks[i];
	  off+=take; n-=take; ctr++;
	}
}

static int pk_recv(void *ctx)
{
	uint8_t nonce[12],ks[64],polyKey[32],tag[16],lenb[4];
	size_t n,i,pad;
	if(sb_pull(ctx,4)) return -1;
	if(!st_r){
	{ n=tbe32(sbuf+so);	/* content = padLen || payload || pad */
	  if(n<2||n+4>sizeof rpl+8) return -1;
	  if(sb_pull(ctx,4+n)) return -1;
	  pad=(size_t)sbuf[so+4];
	  if(pad+1>n) return -1;
	  rn=n-1-pad; rp=0;
	  tcpy(rpl,sbuf+so+5,rn);
	  so+=4+n; seq_r++; return 0;
	}
	}
	/* length prefix decrypted with lengthKey = key_r[32:64], counter 0 */
	{ mk_nonce(nonce,seq_r);
	  ch20_gen(key_r+32,nonce,0,ks,4);
	  for(i=0;i<4;i++) lenb[i]=(uint8_t)(ks[i]^sbuf[so+i]);
	  n=tbe32(lenb); }
	if(n>60000){ SLOG("pk_recv: bad len %u",(unsigned)n); return -1; }
	if(sb_pull(ctx,4+n+16)) return -1;
	{ ch20_gen(key_r,nonce,0,ks,32);
	  for(i=0;i<32;i++) polyKey[i]=ks[i]; }
	/* tag over encLen || ciphertext; content decrypted afterwards */
	p1305(tag,sbuf+so,4+n,polyKey);
	xch_xor(key_r,nonce,1,sbuf+so+4,n);
	{ int bad=0; for(i=0;i<16;i++) bad|=(tag[i]^sbuf[so+4+n+i]);
		if(bad){ SLOG("pk_recv: tag mismatch len=%u",(unsigned)n); return -1; } }
	/* content = padByte || payload || pad */
	pad=(size_t)sbuf[so+4];
	if(pad+1>n) return -1;
	rn=n-1-pad; rp=0;
	#ifdef DIAG_MARK
	if(sbuf[so+5]==80) SLOG("raw80 pad=%u n=%u b=%u %u %u %u %u %u %u %u %u %u %u",(unsigned)pad,(unsigned)n,(unsigned)sbuf[so+4],(unsigned)sbuf[so+5],(unsigned)sbuf[so+6],(unsigned)sbuf[so+7],(unsigned)sbuf[so+8],(unsigned)sbuf[so+9],(unsigned)sbuf[so+10],(unsigned)sbuf[so+11],(unsigned)sbuf[so+12],(unsigned)sbuf[so+13],(unsigned)sbuf[so+14]);
	#endif
	tcpy(rpl,sbuf+so+5,rn);
	so+=4+n+16;
	{ seq_r++; return 0; }
}

/* advertised algorithms: x/crypto v0.55.0 defaults, filtered to the
 * curve25519 KEX + chacha20-poly1305 record cipher */
static const char *a_kex[]={"curve25519-sha256","curve25519-sha256@libssh.org"};
static const char *a_host[]={"ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521","ssh-ed25519","rsa-sha2-512","rsa-sha2-256","ssh-rsa"};
static const char *a_ciph[]={"chacha20-poly1305@openssh.com"};
static const char *a_mac[]={"hmac-sha2-256-etm@openssh.com","hmac-sha2-512-etm@openssh.com","hmac-sha2-256","hmac-sha2-512","hmac-sha1"};
static const char *a_comp[]={"none"};

static uint8_t H32[32],sessionId[32],K[70],ourPub[32];
/* rekey: the exchange hash of a rekey reuses the ORIGINAL version strings and
   keeps the ORIGINAL sessionId (x/crypto handshake.go: firstKeyExchange only
   sets sessionID on the first KEX). Save V_C/V_S verbatim at handshake. */
static uint8_t g_vc[64], g_vs[256]; static size_t g_vcn, g_vsn;
static uint8_t nkey_w[64], nkey_r[64];   /* pending new keys, swapped after NEWKEYS */


/* stream layer (SSHConn.RingBuffer analogue): sbuf[so..sn) holds unconsumed
 *  bytes across WS messages; consumed prefix is dropped. Decrypt in place,
 *  never re-touching bytes already handed out. */
static int sb_pull(void *ctx,size_t n)
{
    while(sn-so<n){
        int p=0,r;
        if(so){ tcpy(sbuf,sbuf+so,sn-so); sn-=so; so=0; }
        if(sn>=sizeof sbuf) return -1;
        r=ws_get(ctx,sbuf+sn,&p,(int)sizeof sbuf-1-(int)sn);
        if(r<0) return -1;   /* negative = transport error/EOF: end stream so caller reconnects */
        sn+=(size_t)p;
    }
	return 0;
}
static int tpfx(const void *b,const char *s){ const unsigned char *p=(const unsigned char*)b; for(;;s++,p++){ if(*s){ if(*p!=(unsigned char)*s) return 0; } else return 1; } }
static int rd_bytes(uint8_t *dst,size_t cap,size_t *outn){
	uint32_t l;
	if(rp+4>rn) return -1;
	l=tbe32(rpl+rp);
	if(l>rn-(rp+4)) return -1;
	if(dst&&l>cap) return -1;
	if(dst) tcpy(dst,rpl+rp+4,l);
	{ rp+=4+l; if(outn) *outn=(size_t)l; }
	return 0;
}
static uint32_t rd_u32(void){ uint32_t v=0; if(rp+4<=rn){ v=tbe32(rpl+rp); rp+=4; } return v; }
static char rdstrbuf[4096];
static const char *rd_str(void){ uint32_t l; if(rp+4>rn) return 0; l=tbe32(rpl+rp); if(l>rn-(rp+4)||l>=sizeof rdstrbuf) return 0; tcpy(rdstrbuf,rpl+rp+4,l); rdstrbuf[l]=0; rp+=4+l; return rdstrbuf; }
/* name-list: copy first entry, count entries, skip whole list */
static int rd_nl(char *out,int cap,int *cnt){
	uint32_t l,j,e; int n=1,w;
	if(rp+4>rn) return -1;
	l=tbe32(rpl+rp);
	if(l>rn-(rp+4)) return -1;
	{ for(j=0;j<l;j++) if(rpl[rp+4+j]==',') n++; }
	{ if(out&&cap>0){
	  e=0; while(e<l&&rpl[rp+4+e]!=',') e++;
	  for(j=0;j<e&&(int)j<cap-1;j++) out[j]=(char)rpl[rp+4+j];
	  w=(int)e; if(w>cap-1) w=cap-1; out[w]=0;
	} }
	rp+=4+l; if(cnt) *cnt=n;
	return 0;
}
/* is `name` an entry of the wire name-list slice [list,list+n)? */
static int nl_has(const char *list,size_t n,const char *name)
{
	size_t i=0,m,j;
	for(;;){
		m=0; while(name[m]) m++;
		if(i+m<=n){
			int ok=1;
			{ for(j=0;j<m;j++) if(list[i+j]!=name[j]){ ok=0; break; } }
			if(ok&&(i+m==n||list[i+m]==',')) return 1;
		}
		while(i<n&&list[i]!=',') i++;
		if(i>=n) return 0;
		i++;
	}
}

static int hv_mode;

static int ss_handshake(void *ctx)
{
	const char *me="SSH-chisel-v3-client";
	uint8_t priv[32],pub[32],peerPub[32],hk[192],vline[64];
	uint8_t theirVer[256];
	char kexName[64],cipherName[64];
	size_t vl,vcr,hkLen,peerLen,kl,k;
	int j,nl,err;
	/* 1. version line: its own raw WS frame, CRLF-terminated */
	{ for(k=0;k<20;k++) vline[k]=(uint8_t)me[k];
	  vline[20]=13; vline[21]=10;
	  if(ws_put(ctx,vline,22)){ SLOG("handshake: ws write err=%d",WSAGetLastError()); return -1; }
	}
	/* their version line: raw stream bytes up to '\n' */
	{ for(k=0;;k++){
	  if(so+k<sn){ if(sbuf[so+k]=='\n') break; }
	  else { int spr=sb_pull(ctx,k+1); if(spr){ SLOG("scan k=%d spr=%d rn=%d so=%d sn=%d",(int)k,spr,(int)rn,(int)so,(int)sn); return -1; } }
	}
	  vcr=k;
	  if(vcr>sizeof theirVer-3) return -1;
	  vl=vcr; if(vl&&sbuf[so+vl-1]=='\r') vl--;
	  tcpy(theirVer,sbuf+so,vcr);
	  so+=k+1;
	}
	/* 2. kexInit(20): cookie(16) + 10 name-lists + bool + u32 */
	pn=0;
	w_u8(20);
	for(j=0;j<16;j++) w_u8((uint8_t)trndb());
	w_nlist(a_kex,2); w_nlist(a_host,7);
	w_nlist(a_ciph,1); w_nlist(a_ciph,1);
	w_nlist(a_mac,5); w_nlist(a_mac,5);
	w_nlist(a_comp,1); w_nlist(a_comp,1);
	w_u32(0); w_u32(0);
	w_bool(0); w_u32(0);
	wb_reset();
	{ size_t an=(hv_mode==1||hv_mode==3)?22:20, bn=(hv_mode>=2)?vcr:vl;
	  wb_str(vline,an); wb_str(theirVer,bn);
	  g_vcn=an; tcpy(g_vc,vline,an); g_vsn=bn; tcpy(g_vs,theirVer,bn);
	  SLOG("hver our=%u their=%u",(unsigned)an,(unsigned)bn);
	}
	wb_str(pb,pn);
	if(pk_send(ctx)){ SLOG("handshake: ws write err=%d",WSAGetLastError()); return -1; }
	/* 3. their kexInit: hash it verbatim, then check the negotiation */
	if(pk_recv(ctx)){ SLOG("hs: recv %d len=%d",(int)__LINE__,(int)rn); return -1; }
	SLOG("kextype=%d len=%d",(int)rpl[0],(int)rn);
	wb_str(rpl,rn);
	{ rp=1;
	  if(rp+16>rn){ SLOG("hs: cook %d",(int)__LINE__); return -1; }
	  rp+=16;
	  { uint32_t l; const char *pp; int f=0,j2;
		/* 1. peer kex list */
		if(rp+4>rn){ SLOG("hs: kxhdr %d",(int)__LINE__); return -1; }
		l=tbe32(rpl+rp); pp=(const char*)(rpl+rp+4);
		if(rd_nl(kexName,sizeof kexName,&nl)){ SLOG("hs: kexnl %d",(int)__LINE__); return -1; }
		{ for(j2=0;j2<(int)(sizeof a_kex/sizeof a_kex[0]);j2++) if(nl_has(pp,l,a_kex[j2])){ f=1; break; } }
		if(!f){ SLOG("hs: no mutual kex (peer first %s)",kexName); return -1; }
		/* 2. peer host-sig list */
		if(rd_nl(0,0,&nl)){ SLOG("hs: hostnl %d",(int)__LINE__); return -1; }
		/* 3. peer cipher list */
		if(rp+4>rn){ SLOG("hs: ciphdr %d",(int)__LINE__); return -1; }
		l=tbe32(rpl+rp); pp=(const char*)(rpl+rp+4);
		if(rd_nl(cipherName,sizeof cipherName,&nl)){ SLOG("hs: cipnl %d",(int)__LINE__); return -1; }
		if(!nl_has(pp,l,a_ciph[0])){ SLOG("hs: no mutual cipher (peer first %s)",cipherName); return -1; }
		/* 4-8. cipher repeat, mac x2, comp x2 */
		{ for(j2=0;j2<5;j2++) if(rd_nl(0,0,&nl)){ SLOG("hs: nl %d",(int)__LINE__); return -1; } }
	  }
	}
	/* 4. msgKex(30): string(our 32-byte curve pubkey) */
	{ for(j=0;j<32;j++) priv[j]=(uint8_t)trndb();
	  x25519_clamp(priv);
	  x25519_base(priv,pub);
	  tcpy(ourPub,pub,32);
	}
	pn=0; w_u8(30); w_bytes(pub,32);
	if(pk_send(ctx)){ SLOG("hs: kex send %d",(int)__LINE__); return -1; }
	if(pk_recv(ctx)){ SLOG("hs: kex recv %d",(int)__LINE__); return -1; }
	if(rn<1||rpl[0]!=31){ SLOG("hs: notkexreply type=%d len=%d",(int)rpl[0],(int)rn); return -1; }
	{
	  rp=1;
	  if(rd_bytes(hk,sizeof hk,&hkLen)){ SLOG("hs: hk %d len=%d",(int)__LINE__,(int)rn); return -1; }
	  if(rd_bytes(peerPub,32,&peerLen)){ SLOG("hs: peer %d len=%d",(int)__LINE__,(int)rn); return -1; }
	  if(peerLen!=32){ SLOG("hs: peerlen %d len=%d",(int)peerLen,(int)rn); return -1; }
	}
	/* 5. H = sha256(magics writeStrings || hostKey || ourPub || peerPub || mpint K) */
	wb_str(hk,hkLen);
	wb_str(pub,32);
	wb_str(peerPub,32);
	{ uint8_t secret[32];
	  x25519_scalarmul(priv,peerPub,secret);
	  kl=mpint_payload(secret,32,K);
	  wb_raw(K,kl);
	}
	sha256_hash(wb,wn,H32);
	tcpy(sessionId,H32,32);
	ssh_kdf(key_w,64,K,kl,H32,sessionId,32,'C');
	ssh_kdf(key_r,64,K,kl,H32,sessionId,32,'D');
	/* 6. NEWKEYS travels plaintext; write cipher activates after it */
	pn=0; w_u8(21);
	err=pk_send(ctx);
	st_w=1;
	if(err){ SLOG("handshake: ws write err=%d",WSAGetLastError()); return -1; }
	return 0;
}

/* ---- rekey: the server starts a new KEX after 1 GiB of server->client data
   (chacha20 rekeyBytes = 1<<30).  A 10-minute browse exceeds that, so the
   server sends KEXINIT(20) mid-session; if we ignore it, x/crypto queues every
   later packet (incl. the keepalive ping) in pendingPackets and blocks, the
   ping times out, and the session dies at 125s.  This runs the same
   curve25519 + chacha20-poly1305 exchange as the handshake but ENCRYPTED under
   the current keys, reusing the ORIGINAL version strings and the ORIGINAL
   sessionId (sessionID is only set on the first KEX).  seq_w/seq_r CONTINUE
   (non-strict KEX).  ti/tin = the server's KEXINIT packet we just received. ---- */
static int do_rekey(void *ctx, const uint8_t *ti, size_t tin)
{
	uint8_t priv[32],pub[32],peerPub[32],hk[192];
	size_t hkLen,peerLen,kl;
	int j,err;
	SLOG("rekey: start tin=%u",(unsigned)tin);
	/* transcript: original V_C || V_S || our new KEXINIT || their KEXINIT */
	wb_reset();
	wb_str(g_vc,g_vcn); wb_str(g_vs,g_vsn);
	/* our KEXINIT(20): fresh cookie, same algorithms as the handshake */
	pn=0; w_u8(20);
	for(j=0;j<16;j++) w_u8((uint8_t)trndb());
	w_nlist(a_kex,2); w_nlist(a_host,7);
	w_nlist(a_ciph,1); w_nlist(a_ciph,1);
	w_nlist(a_mac,5); w_nlist(a_mac,5);
	w_nlist(a_comp,1); w_nlist(a_comp,1);
	w_u32(0); w_u32(0);
	w_bool(0); w_u32(0);
	wb_str(pb,pn);
	if(pk_send(ctx)){ SLOG("rekey: kexinit send %d",(int)__LINE__); return -1; }
	wb_str(ti,tin);
	/* KEX_ECDH_INIT(30): fresh curve25519 pair */
	{ for(j=0;j<32;j++) priv[j]=(uint8_t)trndb();
	  x25519_clamp(priv);
	  x25519_base(priv,pub);
	}
	pn=0; w_u8(30); w_bytes(pub,32);
	if(pk_send(ctx)){ SLOG("rekey: ecdhinit send %d",(int)__LINE__); return -1; }
	if(pk_recv(ctx)){ SLOG("rekey: ecdhreply recv %d",(int)__LINE__); return -1; }
	if(rn<1||rpl[0]!=31){ SLOG("rekey: not reply type=%d len=%d",(int)rpl[0],(int)rn); return -1; }
	{ rp=1;
	  if(rd_bytes(hk,sizeof hk,&hkLen)){ SLOG("rekey: hk %d",(int)__LINE__); return -1; }
	  if(rd_bytes(peerPub,32,&peerLen)){ SLOG("rekey: peer %d",(int)__LINE__); return -1; }
	  if(peerLen!=32){ SLOG("rekey: peerlen %d",(int)peerLen); return -1; }
	}
	wb_str(hk,hkLen);
	wb_str(pub,32);
	wb_str(peerPub,32);
	{ uint8_t secret[32];
	  x25519_scalarmul(priv,peerPub,secret);
	  kl=mpint_payload(secret,32,K);
	  wb_raw(K,kl);
	}
	sha256_hash(wb,wn,H32);
	/* sessionId UNCHANGED for rekey */
	ssh_kdf(nkey_w,64,K,kl,H32,sessionId,32,'C');
	ssh_kdf(nkey_r,64,K,kl,H32,sessionId,32,'D');
	/* NEWKEYS(21) travels under the OLD write key; swap after it is sent */
	pn=0; w_u8(21);
	err=pk_send(ctx);
	if(err){ SLOG("rekey: newkeys send %d",(int)__LINE__); return -1; }
	tcpy(key_w,nkey_w,64);
	/* their NEWKEYS(21) arrives under the OLD read key; swap after */
	if(pk_recv(ctx)){ SLOG("rekey: newkeys recv %d",(int)__LINE__); return -1; }
	if(rn<1||rpl[0]!=21){ SLOG("rekey: not newkeys type=%d len=%d",(int)rpl[0],(int)rn); return -1; }
	tcpy(key_r,nkey_r,64);
	SLOG("rekey: done seq_w=%u seq_r=%u",(unsigned)seq_w,(unsigned)seq_r);
	return 0;
}

/* ---- channel + tunnel state: one entry per concurrent peer connection ----
 *   Each browser tab connection, RDP client, SMB or LDAP client opens its own
 *   tunnel connection, so each gets its own channel record (id, write window,
 *   target socket, SOCKS request state). */

#define CH_W   2097152u
#define CH_MAX 32768u
#define CH_N   256   /* concurrent channels (one per proxied connection). 64 was
   too tight for real browsing: YouTube's parallel CDN/segment connections burst
   past 64, and the 65th+ open was refused with "channel table full" (graceful,
   session-safe, but the connection failed). 256 covers realistic bursts. The
   pump's select() still watches <=64 fds (winsock FD_SETSIZE); channels beyond
   that are serviced by pump_round on every peer-packet wake (frequent under
   load) and the 1s select-timeout floor, so no channel starves. */
#define PEND_N 16384
struct channel {
	uint32_t id, win, adj;
	int fd;                  /* target socket, -1 until dialed / after teardown */
	int stage;               /* socks5 request state: 0..5 parsing, 6 relaying */
	int meth_cnt;           /* socks5 method count during negotiation */
	int socks_msel;         /* chosen socks5 method byte (00/01) during negotiation */
	size_t sbn, pendn;
	uint8_t sb[4096], pend[PEND_N];
	char tgt_host[72]; int tgt_port;
	int ufd[4];              /* UDP target sockets keyed by usrc (stage 7) */
	char usrc[4][64];        /* gob udpPacket.Src, echoed on replies */
	int used;
	int eof_sent, wr_closed, wait_eof;   /* 96 sent / 96 received / target EOF but pend still queued */
};
static struct channel chs[CH_N];
static struct channel *C;    /* the channel the helpers below are working on */

static int ch_eof(struct channel *c,void *ctx);   /* defined below with the channel helpers */
/* peer write-window flow control: queue bytes, release as the window grows */
static int flush_pend(void *ctx)
{
	while(C->pendn){
		size_t n=C->pendn;
		if(n>(size_t)C->win) n=(size_t)C->win;
		if(n>CH_MAX) n=CH_MAX;
		if(!n) break;
		pn=0; w_u8(94); w_u32(C->id); w_bytes(C->pend,n);
		{ int r=pk_send_nb(ctx);
		  if(r<0) return -1;
		  /* 2 = refused, nothing went out: keep pend intact, retry next pump pass.
		     0/1 = the frame is COMMITTED (fully written, or parked in the outbox for
		     ws_outbox_flush to finish it) - those n bytes leave the queue and charge
		     the channel window EXACTLY once.  Treating 1 as "not sent" re-sent the
		     same payload to the server (duplicated stream bytes) while `win` stayed
		     inflated, so the server's own receive window ran short and
		     vendored/ssh/channel.go:336 aborted the WHOLE session with
		     "ssh: remote side wrote too much". */
		  if(r==2) break; }
		{ size_t i; for(i=0;i<C->pendn-n;i++) C->pend[i]=C->pend[n+i]; }
		if(C->stage==7) DM(9035);
		C->pendn-=n; C->win-=n;
	}
	if(C->pendn){ static unsigned fstall=0; if((fstall++&511u)==0) SLOG("flush stall pend=%u win=%u f=%u",(unsigned)C->pendn,(unsigned)C->win,fstall); }
	/* The target reached EOF while bytes were still parked for lack of window
	   credit: the queue is empty now, so the deferred 96 can finally go out. */
	if(C->wait_eof && !C->pendn){ C->wait_eof=0; ch_eof(C,ctx); }
	return 0;
}
static int queue_data(void *ctx,const uint8_t *p,size_t n)
{
	while(n){
		size_t m=n;
		if(C->pendn+m>PEND_N) m=PEND_N-C->pendn;
		if(!m){ size_t before=C->pendn; if(flush_pend(ctx)) return -1; if(C->pendn==before) return -1; continue; }
		tcpy(C->pend+C->pendn,p,m); C->pendn+=m; p+=m; n-=m;
		if(flush_pend(ctx)) return -1;
	}
	return 0;
}
/* Deliberately NO second channel-data emitter: flush_pend is the only place that
   builds a t=94 frame, so every payload byte is charged against the channel
   window exactly once.  The SOCKS handshake replies used to go through a
   `send_now` helper that skipped that accounting: 12 B per channel (2 B method
   reply + 10 B connect reply) permanently ahead of the server's window, enough
   for the boundary-exact final flush of a window-stalled channel to trip
   "ssh: remote side wrote too much" and take the whole session down with it. */
static int chan_close(void *ctx)
{ SLOG("tx close id=%u stage=%d",(unsigned)C->id,(int)C->stage); pn=0; w_u8(97); w_u32(C->id); return pk_send(ctx); }
static int chan_eof(void *ctx)
{ SLOG("tx eof id=%u stage=%d",(unsigned)C->id,(int)C->stage); pn=0; w_u8(96); w_u32(C->id); return pk_send(ctx); }
static int chan_confirm(void *ctx)
{ pn=0; w_u8(91); w_u32(C->id); w_u32(C->id); w_u32(CH_W); w_u32(CH_MAX); return pk_send(ctx); }
static int chan_seen=0;   /* a 90-open landed in this session: pump idle policy can end it */
static struct channel *ch_get(uint32_t id)
{ int i; for(i=0;i<CH_N;i++) if(chs[i].used && chs[i].id==id) return chs+i; return 0; }
static struct channel *ch_new(uint32_t id)
{
	int i;
	for(i=0;i<CH_N;i++) if(!chs[i].used){
		struct channel *c=chs+i;
		c->used=1; c->id=id; c->win=CH_W; c->adj=0; c->fd=-1; chan_seen=1;
		c->stage=0; c->meth_cnt=0; c->socks_msel=0; c->sbn=0; c->pendn=0; c->eof_sent=0; c->wr_closed=0; c->wait_eof=0;
		c->tgt_host[0]=0; c->tgt_port=0;
		{ int j; for(j=0;j<4;j++){ c->ufd[j]=-1; c->usrc[j][0]=0; } }
		C=c; return c;
	}
	return 0;
}
static int ch_live(void)
{ int i,n=0; for(i=0;i<CH_N;i++) if(chs[i].used && chs[i].fd>=0) n++; return n; }
static int ch_any(void)
{ int i,n=0; for(i=0;i<CH_N;i++) if(chs[i].used) n++; return n; }
static void ch_drop(struct channel *c)
{ int j;
  if(c->fd>=0){ SLOG("drop ch%u fd=%d",c->id,c->fd); closesocket(c->fd); c->fd=-1; }
  for(j=0;j<4;j++) if(c->ufd[j]>=0){ closesocket(c->ufd[j]); c->ufd[j]=-1; c->usrc[j][0]=0; }
  c->used=0; if(C==c) C=0; }
static int ch_eof(struct channel *c,void *ctx)
{ if(!c->eof_sent){ C=c; chan_eof(ctx); c->eof_sent=1; } return 0; }
/* Target hit EOF: it will produce nothing more, but bytes we already ACCEPTED
   may still be parked waiting for window credit.  SSH 96 means "no more data
   from me", so emitting it while pend is non-empty ends the stream on the
   server and the parked bytes are lost - measured as every window-stalled
   download coming back 1-9 KB short of the real response.  Keep the channel
   alive (socket included: the server may still write to the target) and hold
   the 96 until flush_pend has emptied the queue. */
static int ch_eof_done(struct channel *c,void *ctx)
{ if(c->pendn){ c->wait_eof=1; return 0; } return ch_eof(c,ctx); }
static int ch_kill(struct channel *c,void *ctx)
{ C=c; ch_eof(c,ctx); chan_close(ctx); ch_drop(c); return 0; }
/* openFailure (92): the server's openChannel is blocked awaiting 91/92/97 for
 * this id; ANY other packet (e.g. a 96) kills its mux loop
 * ("unexpected packet in response to channel open"). Drop our slot first, then
 * answer the open with 92. */
static int chan_open_fail(void *ctx,uint32_t id,const char *why)
{ if(C&&C->used&&C->id==id) ch_drop(C);
  pn=0; w_u8(92); w_u32(id); w_u32(5); w_str(why); w_str("en"); return pk_send(ctx); }

/* ---- auth (x/crypto client_auth.go: serviceRequest 5 -> serviceAccept 6,
 *      then userAuthRequest 50; success = 52) ---- */
/* next application packet; a msgNewKeys (21) packet switches the read
 * cipher and is skipped */
static int rx_packet(void *ctx,int *type)
{
	for(;;){
		if(pk_recv(ctx)) return -1;
		if(rn<1) return -1;
		if(rpl[0]==21){ st_r=1; continue; }
		SLOG("rx: pkt %d len=%d",(int)rpl[0],(int)rn);
		*type=(int)rpl[0];
		return 0;
	}
}
static int auth_read(void *ctx)
{
	int t;
	for(;;){
		if(rx_packet(ctx,&t)) return -1;
		if(t==52) return 0;           /* userAuthSuccess */
		if(t==51){
			/* USERAUTH_FAILURE from a Go server.  x/crypto marshals this with the field
			   order of userAuthFailureMsg{ Methods []string; PartialSuccess bool }, so on
			   the wire the name-list comes FIRST and the boolean SECOND - the reverse of
			   RFC 4252 §5.1 (Go peers agree with each other, so only a non-Go client
			   notices; measured against chisel 1.12.1: 51 | 00 00 00 08 | "password" | 00).
			   Worth logging: it is how you tell "this server has --auth set" from one that
			   would have accepted us. */
			char methods[80]; int cnt=0, partial=0;
			rp=1;
			if(rd_nl(methods,(int)sizeof methods,&cnt)==0){
				partial=(rp<rn)?(int)rpl[rp]:0;
				SLOG("auth failure: methods=[%s] count=%d partial=%d",methods,cnt,partial);
			} else SLOG("auth failure: no method list (rn=%d)",(int)rn);
			return 1; }
		if(t==3) return 1;            /* unimplemented: try the next method */
		if(t==53 || t==60) continue;  /* banner / info request */
		SLOG("auth: unexpected msg %d",t);
		return -1;
	}
}
static int ss_auth(void *ctx,const char *user,const char *pass)
{
	int r,t;
	pn=0; w_u8(5); w_str("ssh-userauth");
	if(pk_send(ctx)) return -1;
	if(rx_packet(ctx,&t)) return -1;
	if(t!=6){ SLOG("auth: no service accept (msg %d)",t); return -1; }
	pn=0; w_u8(50); w_str(user); w_str("ssh-connection"); w_str("none");
	if(pk_send(ctx)) return -1;
	r=auth_read(ctx);
	if(r==0) return 0;
	pn=0; w_u8(50); w_str(user); w_str("ssh-connection"); w_str("password");
	w_bool(0); w_str(pass);
	if(pk_send(ctx)) return -1;
	return auth_read(ctx)==0?0:-1;
}

/* ---- config request: global 80 "config", JSON body (settings.EncodeConfig) ---- */
static void j_lit(char *o,size_t *n,size_t cap,const char *s){ const char *p=s; while(*p){ if(*n+1<cap) o[(*n)++]=*p; p++; } }
static void j_esc(char *o,size_t *n,size_t cap,const char *s){ const char *p=s; int c; for(;(c=(unsigned char)*p);p++){ if(c=='"'||c=='\\'){ if(*n+2<cap){ o[(*n)++]='"'; o[(*n)++]=c; } } else if(c<32){ if(*n+6<cap){ const char *h="0123456789abcdef"; o[(*n)++]='\\'; o[(*n)++]='u'; o[(*n)++]='0'; o[(*n)++]='0'; o[(*n)++]=h[c>>4]; o[(*n)++]=h[c&15]; } } else if(*n+1<cap) o[(*n)++]=c; } }
static int dec(int v,char *d,int cap){ char t[8]; int k=0,j,n=0; if(!v) t[k++]='0'; else while(v){ t[k++]=(char)('0'+v%10); v/=10; } for(j=k-1;j>=0&&n<cap-1;j--) d[n++]=t[j]; d[n]=0; return n; }

static int ss_config(void *ctx,const char *id,const char *lhost,int lport,const char *rhost,int rport,int ubind,const char *urehost,int ureport)
{
	char body[1024]; size_t bn=0,cap=sizeof body;
	j_lit(body,&bn,cap,"{\"Version\":\""); j_esc(body,&bn,cap,id); j_lit(body,&bn,cap,"\",\"Remotes\":[{\"LocalHost\":\"");
	j_esc(body,&bn,cap,lhost); j_lit(body,&bn,cap,"\",\"LocalPort\":\"");
	{ char t[8]; dec(lport,t,8); j_esc(body,&bn,cap,t); }
	j_lit(body,&bn,cap,"\",\"LocalProto\":\"tcp\",\"RemoteHost\":\"");
	j_esc(body,&bn,cap,rhost); j_lit(body,&bn,cap,"\",\"RemotePort\":\"");
	{ char t[8]; if(rport) dec(rport,t,8); t[0]=0; j_esc(body,&bn,cap,t); }
	j_lit(body,&bn,cap,"\",\"RemoteProto\":\"tcp\",\"Socks\":");
	{ j_lit(body,&bn,cap,rhost[0]||rport?"false":"true"); }
	j_lit(body,&bn,cap,",\"Reverse\":true,\"Stdio\":false}");
	if(ubind>0&&urehost[0]){
		j_lit(body,&bn,cap,",{\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"");
		{ char t[8]; dec(ubind,t,8); j_esc(body,&bn,cap,t); }
		j_lit(body,&bn,cap,"\",\"LocalProto\":\"udp\",\"RemoteHost\":\"");
		j_esc(body,&bn,cap,urehost); j_lit(body,&bn,cap,"\",\"RemotePort\":\"");
		{ char t[8]; dec(ureport,t,8); j_esc(body,&bn,cap,t); }
		j_lit(body,&bn,cap,"\",\"RemoteProto\":\"udp\",\"Socks\":false,\"Reverse\":true,\"Stdio\":false}");
	}
	j_lit(body,&bn,cap,"]}");
	pn=0; w_u8(80); w_str("config"); w_bool(1); w_raw(body,bn);
	if(pk_send(ctx)) return -1;
	if(pk_recv(ctx)) return -1;
	if(rn<1) return -1;
	if(rpl[0]==81) return 0;
	{ const char *e="?";
	  if(rpl[0]==82){ rp=1; { const char *m=rd_str(); if(m) e=m; } }
	  SLOG("config rejected: %s (msg %d)",e,(int)rpl[0]);
	}
	return -1;
}

/* ---- socks5-on-channel (go-socks5 ServeConn on the tunnel's client end) ----
 *   Wire: [ver][n][methods..][chosen][ver][cmd][at][addr..][port2].
 *   Tools that name a destination send at=1 (IPv4), at=3 (host string) or
 *   at=4 (IPv6).  Firefox + FoxyProxy (and Chromium's bare "socks" mode) send
 *   at=0 with no address: the request names no destination, so that connect
 *   dials the --tgt default (an endpoint on the machine this client runs on).
 *   Past the connect the pump is a transparent byte relay, so RDP, SMB, LDAP,
 *   HTTP or anything else is copied both ways without parsing. */
static char def_host[72]; static int def_port, def_set;
void ss_set_tgt(const char *h,int p)
{ int i=0; while(h[i]&&i<71){ def_host[i]=h[i]; i++; } def_host[i]=0; def_port=p; def_set=(p>0&&p<65536)?1:0; }

static int socks_reply(void *ctx,uint8_t st,const char *host,int port)
{
	uint8_t r[10];
	r[0]=5; r[1]=st; r[2]=0; r[3]=1;
	{ int i; for(i=0;i<4;i++) r[4+i]=0; }
	(void)host;
	r[8]=(uint8_t)(port>>8); r[9]=(uint8_t)port;
	(void)host;
	return queue_data(ctx,r,10);   /* window-accounted (there is no unaccounted path) */
}
static void ip4_to_str(const uint8_t *ip,char *d){ int j,n=0; for(j=0;j<4;j++){ char t[4]; dec(ip[j],t,4); { int k=0; while(t[k]) d[n++]=t[k++]; } if(j<3) d[n++]='.'; } d[n]=0; }
static int sock_drain(void *ctx);

/* 0 = handled (dialed, or a v5 error reply was written and parsing restarted);
   1 = a tunnel write failed, the caller tears that channel down. */
static int socks_parse(void *ctx)
{
 for(;;){
  if(C->stage==0){
   if(C->sbn<1) return 0;
   if(C->sb[0]!=5){ socks_reply(ctx,0xff,0,0); return 1; }
   { tcpy(C->sb,C->sb+1,C->sbn-1); C->sbn--; }
   C->stage=1; continue;
  }
  if(C->stage==1){
   if(C->sbn<1) return 0;
   C->meth_cnt=C->sb[0];
   { tcpy(C->sb,C->sb+1,C->sbn-1); C->sbn--; }
   C->stage=2; continue;
  }
  if(C->stage==2){
   if((int)C->sbn<C->meth_cnt) return 0;
   { int i,ok=0; C->socks_msel=-1; for(i=0;i<C->meth_cnt;i++) if(C->sb[i]==0||C->sb[i]==1){ C->socks_msel=C->sb[i]; ok=1; break; }
     if(!ok){ socks_reply(ctx,0xff,0,0); return 1; } }
   { tcpy(C->sb,C->sb+C->meth_cnt,C->sbn-(size_t)C->meth_cnt); C->sbn-=C->meth_cnt; }
  { uint8_t a[2]; a[0]=5; a[1]=(uint8_t)C->socks_msel; if(queue_data(ctx,a,2)) return 1; } /* auth reply: echo the chosen method */
   C->stage=3; continue;
  }
  if(C->stage==3){
   while(C->sbn>0&&C->sb[0]!=5){ C->sbn--; tcpy(C->sb,C->sb+1,C->sbn); }
   if(C->sbn<1) return 0;
   if(C->sb[1]==0&&C->sbn>=2){ if(C->sbn>=3&&C->sb[2]==5){ tcpy(C->sb,C->sb+2,C->sbn-2); C->sbn-=2; continue; } tcpy(C->sb,C->sb+2,C->sbn-2); C->sbn-=2; C->stage=4; continue; } /* 05 00: module auth noise if another 05 follows; else injection between version and cmd */
   if(C->sbn<2) return 0;
   if(C->sb[1]!=1){ socks_reply(ctx,7,0,0); return 1; }
    { tcpy(C->sb,C->sb+2,C->sbn-2); C->sbn-=2; } /* consume version+command ONLY; address type stays for stage 4 */
   C->stage=4; continue;
  }
  if(C->stage==4){
   { uint8_t at; int need,hn,i;
    rep:;
    if(C->sbn<1) return 0;
    at=C->sb[0]; hn=0; need=0;
    if(at==0&&C->sbn>=2&&(C->sb[1]==1||C->sb[1]==3||C->sb[1]==4)){ tcpy(C->sb,C->sb+1,C->sbn-1); C->sbn--; goto rep; } /* module auth 00 injected before addrtype */
    if(at==0){ need=1; }
     else if(at==1){ need=7; }
     else if(at==3){ if(C->sbn<2) return 0; hn=(int)C->sb[1]; need=4+hn; }
     else if(at==4){ need=19; }
     else { socks_reply(ctx,9,0,0); return 1; }
     if(hn>63){ socks_reply(ctx,3,0,0); return 1; }
     if((int)C->sbn<need) return 0;
     C->tgt_host[0]=0; C->tgt_port=0;
     if(hn){
       for(i=0;i<hn;i++) C->tgt_host[i]=(char)C->sb[2+i];
       C->tgt_host[hn]=0;
       C->tgt_port=((int)C->sb[2+hn]<<8)|(int)C->sb[3+hn];
     }
     else if(at==1){ uint8_t ip4[4]; for(i=0;i<4;i++) ip4[i]=C->sb[1+i]; ip4_to_str(ip4,C->tgt_host); C->tgt_port=((int)C->sb[5]<<8)|(int)C->sb[6]; }
     else if(at==4){ uint8_t ip4[4]; for(i=0;i<4;i++) ip4[i]=C->sb[13+i]; ip4_to_str(ip4,C->tgt_host); C->tgt_port=((int)C->sb[17]<<8)|(int)C->sb[18]; }
     { size_t n=C->sbn-(size_t)need; tcpy(C->sb,C->sb+need,n); C->sbn=n; }
   }
   C->stage=5; continue;
  }
  if(C->stage==5){
   { const char *h=C->tgt_host; int p=C->tgt_port, sd;
     if(!h[0]||p<=0){ h=def_host; p=def_port; }
     if(!h[0]||p<=0||p>65535){
       SLOG("socks: no destination in request and no --tgt default");
      socks_reply(ctx,3,h,p); ch_kill(C,ctx); return 0;
     }
    sd=sock_connect(h,p);
    if(sd<0){
      SLOG("socks dial %s:%d failed err=%d",h,p,WSAGetLastError());
      socks_reply(ctx,4,h,p);
      /* stock chisel closes the channel after a failed CONNECT: the peer
         stops sending and half-closes; leaving the slot at stage 0 waiting
         for another request deadlocks it against the server's 96-wait and
         leaks a table slot per failed dial. */
      ch_kill(C,ctx); return 0;
    }
    C->fd=sd;
     SLOG("socks dial %s:%d ok fd=%d",h,p,C->fd);
     if(socks_reply(ctx,0,h,p)) return 1;
     C->stage=6;
     { int dr=sock_drain(ctx); if(dr==2) return 1; if(dr==1) ch_eof_done(C,ctx); }
   }
   return 0;
  }
  break;
 }
 return 0;
}

/* ---- local target relay (BSD winsock send/recv, 4-arg): transparent pump ---- */
static int sock_send_all(int fd,const uint8_t *p,size_t n)
{
 size_t off=0; int stalled=0;
 while(off<n){
  int r=send(fd,(const char*)(p+off),(int)(n-off),0);
  if(r>0){ off+=(size_t)r; continue; }
  if(WSAGetLastError()!=WSA_WOULD_BLOCK) return -1;
  /* The target has stopped reading (hung RDP/SMB share, firewalled peer).  This
     is the ONE thread that also services TLS, the WebSocket, the server's 25 s
     ping and every other channel: a tight WOULD_BLOCK loop here stops us
     answering pings and the server tears down the WHOLE session ~125 s later,
     taking every other tunnel with it.  Wait for writability instead, bounded -
     past ~30 s give up and let the caller kill THIS channel only. */
  if(++stalled>300){ SLOG("tgt fd %d write stalled %u/%u bytes: dropping channel",fd,(unsigned)off,(unsigned)n); return -1; }
  { fd_set1 w; tv1 tv; w.fd_count=1; w.fd_array[0]=(unsigned long long)fd; tv.sec=0; tv.usec=100000;
    if(select(0,0,&w,0,&tv)<0) return -1; }
  if((stalled&127)==1) SLOG("tgt fd %d write stalled at %u/%u",(unsigned)fd,(unsigned)off,(unsigned)n);
 }
 return 0;
}

/* Drain whatever the target has produced right now, without ever blocking the
 *  pump.  This winsock's recv(flags!=0) is MSG_PEEK: it returns immediately
 *  (r<=0 when nothing is buffered) and does NOT consume.  So poll with flags=1
 *  and only then consume exactly the peeked count with a flags=0 read, which
 *  cannot block because those bytes are already in the buffer.  Bytes for one
 *  channel can never starve another channel, the property chisel's Go cio.Pipe
 *  gets from async sockets.  A real EOF/error tears that channel only (96/97). */
static int sock_drain(void *ctx)
{
 char b[1024];
 int r;
 for(;;){
  fd_set1 rs; tv1 tv; tv.sec=0; tv.usec=0; rs.fd_count=1; rs.fd_array[0]=C->fd;
  if(select(0,&rs,0,0,&tv)<=0) return 0; /* nothing buffered now; pump_round re-drains later */
  /* A full peer window is BACKPRESSURE, not death: never recv more than the
     pend can hold, so the remainder parks in the socket buffer (select keeps
     reporting readable) and the next rx93 -> flush_pend resumes the flow.
     queue_data can then only fail on transport death (-1 -> kill channel). */
  { size_t space=PEND_N-C->pendn;
    if(space<sizeof b){ if(flush_pend(ctx)) return 2; space=PEND_N-C->pendn; if(!space) return 0; }
    r=recv(C->fd,b,(int)(space<sizeof b?space:sizeof b),0); /* select said readable: cannot block */
  }
  if(r>0){ if(r<1024) SLOG("tgt fd %d -> %d bytes",C->fd,r); if(queue_data(ctx,(uint8_t*)b,(size_t)r)) return 2; continue; }
  if(r==0){ SLOG("target fd %d eof",C->fd); return 1; }
  { int e=WSAGetLastError(); SLOG("target fd %d err=%d",C->fd,e); return 2; }
 }
}

/* ---- chisel UDP remote: R:<bind>:<dest>:udp.  The server's udpListener
 *   pipes gob-encoded udpPacket{Src,Payload} over the channel (share/tunnel/
 *   udp.go); the client relays each datagram to <dest> and echoes replies
 *   back tagged with the same Src.  Wire form captured from encoding/gob
 *   vectors (2026-10-11): the stream opens with the fixed type-definition
 *   message below; each value = Uvarint(len) ff 80 <instance>, instance =
 *   field-delta pairs 01 <uvlen> <Src> 01 <uvlen> <Payload> 00. ---- */
static const uint8_t gob_def[] = {
	0x2a,0x7f,0x03,0x01,0x01,0x09,'u','d','p','P','a','c','k','e','t',
	0x01,0xff,0x80,0x00,0x01,0x02,0x01,0x03,'S','r','c',0x01,0x0c,0x00,
	0x01,0x07,'P','a','y','l','o','a','d',0x01,0x0a,0x00,0x00,0x00};
static int memeq(const void *a,const void *b,size_t n){ const unsigned char *x=a,*y=b; size_t i; for(i=0;i<n;i++) if(x[i]!=y[i]) return 0; return 1; }
static size_t uv_put(uint8_t *o,size_t n,unsigned long v){
	if(v<=0x7f){ o[n++]=(uint8_t)v; return n; }
	{ int k=0,j; unsigned long t=v; while(t){ k++; t>>=8; }
	  o[n++]=(uint8_t)(0x100-k);
	  for(j=k-1;j>=0;j--) o[n++]=(uint8_t)(v>>(8*j)); }
	return n;
}
static int uv_get(const uint8_t *m,size_t ml,size_t *ip,unsigned long *vp){
	unsigned b; unsigned long v=0; int k,j;
	if(*ip>=ml) return 1;
	b=m[(*ip)++];
	if(b<0x80){ *vp=b; return 0; }
	k=0x100-(int)b; if(k<1||k>4) return 1;
	if(*ip+(size_t)k>ml) return 1;
	for(j=0;j<k;j++) v=(v<<8)|m[(*ip)++];
	*vp=v; return 0;
}
static int udp_send_pkt(void *ctx,const uint8_t *src,size_t sn,const uint8_t *pl,size_t pn)
{
	int slot=-1,i;
	if(!src||sn==0||sn>63||!pl) return 0;   /* malformed: drop the datagram */
	for(i=0;i<4;i++) if(C->ufd[i]>=0&&C->usrc[i][sn]==0&&memeq(C->usrc[i],src,sn)){ slot=i; break; }
	if(slot<0){
		for(i=0;i<4;i++) if(C->ufd[i]<0){ slot=i; break; }
		if(slot<0){ SLOG("udp conns full, dropping"); return 0; }
		{ int fd=sock_udp_dial(C->tgt_host,C->tgt_port);
		  if(fd<0){ SLOG("udp dial %s:%d fail err=%d",C->tgt_host,C->tgt_port,WSAGetLastError()); return 0; }
		  C->ufd[slot]=fd; DM(9032); }
		{ size_t j; for(j=0;j<sn;j++) C->usrc[slot][j]=(char)src[j]; C->usrc[slot][sn]=0; }
	}
	if(send(C->ufd[slot],(const char*)pl,(int)pn,0)<0){ SLOG("udp send err=%d",WSAGetLastError()); return 0; }
	DM(9033);
	SLOG("chan %u udp -> tgt %d bytes",(unsigned)C->id,(int)pn);
	return 0;
}
static int udp_parse(void *ctx)
{
	for(;;){
		size_t off=0,used; unsigned long ml=0;
		if(C->sbn<1) break;
		if(uv_get(C->sb,C->sbn,&off,&ml)){ if(C->sbn<10) break; SLOG("udp: bad gob uvarint"); return 1; }
		if(ml>4000){ SLOG("udp: gob msg too big %d",(int)ml); return 1; }
		if(C->sbn<off+ml) break;   /* partial message; wait for more */
		{ const uint8_t *m=C->sb+off;
		  if(ml>=2&&m[0]==0x7f&&m[1]==0x03){ /* type definition: skip */ }
		  else if(ml>=3&&m[0]==0xff&&m[1]==0x80){
			size_t i=2,sn=0,pn=0; const uint8_t *src=0,*pl=0; int fid=-1; /* gob field deltas count from -1 */
			for(;;){ unsigned long d; if(uv_get(m,ml,&i,&d)) return 1; if(!d) break; fid+=(int)d;
				{ unsigned long L; if(uv_get(m,ml,&i,&L)) return 1; if(i+L>ml) return 1;
				  if(fid==0){ src=m+i; sn=L; } else if(fid==1){ pl=m+i; pn=L; } i+=L; } }
			DM(9031); if(udp_send_pkt(ctx,src,sn,pl,pn)) return 1;
		  }
		  else { SLOG("udp: unknown gob msg %d %d len=%d",(int)m[0],(int)m[1],(int)ml); return 1; }
		}
		used=off+ml;
		{ size_t i; for(i=0;i+used<C->sbn;i++) C->sb[i]=C->sb[i+used]; }
		C->sbn-=used;
	}
	return 0;
}
static int udp_drain(void *ctx)
{
	int s;
	for(s=0;s<4;s++) if(C->ufd[s]>=0){
		fd_set1 rs; tv1 tv; tv.sec=0; tv.usec=0; rs.fd_count=1; rs.fd_array[0]=(unsigned long long)C->ufd[s];
		if(select(0,&rs,0,0,&tv)<=0) continue;
		{ char b[3600]; uint8_t out[3700]; int r=recv(C->ufd[s],b,(int)sizeof b,0);
		  if(r>0){ size_t sn=0,n=0; unsigned long c;
			while(C->usrc[s][sn]&&sn<63) sn++;
			c=2u+1u+(sn>=0x80?2u:1u)+sn+1u+((unsigned)r>=0x80?3u:1u)+(unsigned)r+1u;
			n=uv_put(out,n,c); out[n++]=0xff; out[n++]=0x80; out[n++]=0x01;
			n=uv_put(out,n,(unsigned long)sn);
			{ size_t j; for(j=0;j<sn;j++) out[n+j]=(uint8_t)C->usrc[s][j]; n+=sn; }
			out[n++]=0x01; n=uv_put(out,n,(unsigned long)r);
			{ int j; for(j=0;j<r;j++) out[n+j]=(uint8_t)b[j]; n+=(size_t)r; }
			out[n++]=0x00; DM(9034);
			SLOG("udp fd %d -> chan %u %d bytes",C->ufd[s],(unsigned)C->id,r);
			sdump("ht",out,n>90?90:n);
			if(queue_data(ctx,out,n)) return 1;
		  }
		  else if(r<0){ SLOG("udp recv fd %d err=%d",C->ufd[s],WSAGetLastError()); }
		}
	}
	return 0;
}
/* advance every live channel once; drop channels whose target ended */
static int pump_round(void *ctx)
{
 int i;
 for(i=0;i<CH_N;i++) if(chs[i].used && (chs[i].fd>=0 || chs[i].stage==7 || chs[i].wait_eof)){
  C=chs+i;
  /* blocking drains belong in handle_data right after a target write;
     pump_round flushes pending channel data plus a non-blocking peek-drain
     so live targets keep flowing while the pump services ticker pings. */
  if(C->pendn && flush_pend(ctx)) return -1;
  if(C->used && C->stage==6&&C->fd>=0&&!C->eof_sent&&!C->wait_eof&&(C->pendn<PEND_N||C->win>0)){ int dr=sock_drain(ctx); if(dr==1) ch_eof_done(C,ctx); else if(dr==2) ch_kill(C,ctx); }
  /* ch_kill/ch_drop nulls the global C (ch_drop: if(C==c)C=0) and clears used.
     A target connection erroring mid-stream (CDN RST / rate-limit close - routine
     during video playback) took this path and then line 1066 dereferenced the NULL
     C -> SIGSEGV, killing the whole session. Never touch C after a drop. */
  if(C && C->used && C->stage==7&&udp_drain(ctx)) return -1;
 }
 return 0;
}

/* ---- channel handlers ---- */
static int handle_open(void *ctx)
{
 const char *extra;
 size_t exn;
 uint32_t id;
 (void)ctx;
 rp=1;
 (void)rd_str();
 id=rd_u32();
 (void)rd_u32();
 (void)rd_u32();
 extra=(const char*)(rpl+rp); exn=rn-rp;
 if(ch_get(id)){ SLOG("open dup id=%u (stale slot dropped)",(unsigned)id); ch_drop(ch_get(id)); }
 C=ch_new(id);
 if(!C){ SLOG("channel table full (%d) rej id=%u",CH_N,(unsigned)id);
   #ifdef DIAG_MARK
   { int q; for(q=0;q<CH_N;q++) SLOG("slot %d used=%d id=%u st=%d fd=%d eof=%d wrc=%d pend=%u",(int)q,chs[q].used,(unsigned)chs[q].id,chs[q].stage,chs[q].fd,chs[q].eof_sent,chs[q].wr_closed,(unsigned)chs[q].pendn); }
   #endif
   pn=0; w_u8(92); w_u32(id); w_u32(5); w_str("channel table full"); w_str("en"); return pk_send(ctx); }
  SLOG("open id=%u exn=%d",(unsigned)id,(int)exn);
  #ifdef DIAG_MARK
  { static unsigned opn=0; if((++opn&31u)==0) SLOG("arena off=%u fl=%u",(unsigned)arena_off,(unsigned)(size_t)arena_fl); }
  #endif
 if(exn>4&&teqp(extra+exn-4,"/udp",4)){
   size_t ci=0,j; int found=0;
   for(j=exn-4;j>0;j--) if(extra[j-1]==':'){ ci=j-1; found=1; break; }
   if(!found||ci==0||ci>=sizeof C->tgt_host){ SLOG("bad udp remote: %s",extra); chan_open_fail(ctx,id,"bad udp remote"); return 0; }
   for(j=0;j<ci;j++) C->tgt_host[j]=extra[j]; C->tgt_host[ci]=0;
   { const char *ps=extra+ci+1; C->tgt_port=0; while(*ps>='0'&&*ps<='9'){ C->tgt_port=C->tgt_port*10+(*ps-'0'); ps++; } }
   if(!C->tgt_port){ SLOG("bad udp port: %s",extra); chan_open_fail(ctx,id,"bad udp port"); return 0; }
   C->stage=7; DM(9030);
   SLOG("udp channel to %s:%d",C->tgt_host,C->tgt_port);
   if(chan_confirm(ctx)) return -1;
   if(queue_data(ctx,gob_def,sizeof gob_def)) return -1;
   return 0;
 }
 if(exn==5 && teqp(extra,"socks",5)){ SLOG("socks channel (R:port:socks)"); if(chan_confirm(ctx)) return -1; return 0; }
 SLOG("unknown channel target: %s", extra);
 chan_open_fail(ctx,id,"unsupported target");
 return 0;
}
static int handle_data(void *ctx)
{
 const uint8_t *d;
 size_t dn;
 uint32_t id;
 (void)ctx;
 rp=1;
  id=rd_u32();            /* channelDataMsg: PeersID first, then Length */
  (void)rd_u32();
 d=rpl+rp; dn=rn-rp;
 C=ch_get(id);
 if(!C){ SLOG("data for unknown channel %u (ignored)",(unsigned)id); return 0; }
 /* x/crypto adjustWindow: credit the peer's send window (we declared CH_W
    in the confirm); without this the server stalls after CH_W bytes. */
 C->adj+=(uint32_t)dn;
 if(C->adj>=CH_W/2){ pn=0; w_u8(93); w_u32(C->id); w_u32(C->adj); if(pk_send(ctx)) return -1; C->adj=0; }
 if(C->stage==7){ sdump("hd",d,dn>90?90:dn); }
 if(C->stage<6){
  if(C->sbn+dn>sizeof C->sb){ SLOG("socks request too big"); ch_kill(C,ctx); return 0; }
  { tcpy(C->sb+C->sbn,d,dn); C->sbn+=dn; }
  if(socks_parse(ctx)){ ch_kill(C,ctx); return 0; }
  return 0;
 }
 if(C->stage==7){
  if(C->sbn+dn>sizeof C->sb){ SLOG("udp stream too big"); ch_kill(C,ctx); return 0; }
  { tcpy(C->sb+C->sbn,d,dn); C->sbn+=dn; }
  if(udp_parse(ctx)){ ch_kill(C,ctx); return 0; }
  return 0;
 }
 if(C->fd<0){ SLOG("data on undialed channel %d",(int)id); return 0; }
 SLOG("chan %u -> tgt %d bytes",(unsigned)id,(int)dn);
 if(C->wr_closed){ SLOG("data after peer eof on %u dropped",(unsigned)id); return 0; }
 if(sock_send_all(C->fd,d,dn)){ SLOG("target write fd %d failed err=%d",C->fd,WSAGetLastError()); ch_kill(C,ctx); return 0; }
 SLOG("tgt fd %d wrote %d ok",C->fd,(int)dn);
 { int dr=sock_drain(ctx); if(dr==1) ch_eof_done(C,ctx); else if(dr==2) ch_kill(C,ctx); }
 return 0;
}

/* ---- pump: the session lives until the peer ends it, exactly like a running
 *  chisel client.  A channel dies on its own target EOF/error, on the peer's
 *  channel close (97), or on a refusal (92); the SSH session then keeps
 *  serving further connections.  Bounded self pings keep the pump cycling
 *  between peer packets while a target is still answering. ---- */
/* ---- chisel keepalive (this side pings too) ----
 * The Go tunnel runs the same keepAliveLoop on BOTH ends (share/tunnel/tunnel.go
 * BindSSH -> keepAliveLoop), so a chisel client sends an SSH global request named
 * "ping" with want-reply every --keepalive (default 25s) and requires the reply
 * (81, raw body "pong" - handleSSHRequests does r.Reply(true, []byte("pong"))) within
 * PING_TIMEOUT, which defaults to the keepalive interval.  On timeout it logs
 * "ping failed" and closes the SSH connection.
 *
 * Without our own pings the payload only learns that a transport is dead when the
 * SERVER pings it - which needs the server to be alive.  A black-holed path (front-end
 * idle drop, NAT state expiry, sleep/wake, a server host that vanished without an RST)
 * produces no readable bytes and no error, so the pump would sit in its 1 s select
 * forever and the SOCKS port would stay "bound" over a dead tunnel.  The interval, not
 * per-spin frequency, is what keeps this cheap: a per-spin ping floods the server's
 * request mux (measured: sessions were closing every ~27 s at that rate).
 *
 * ka_ms == 0 disables our pings (chisel's --keepalive 0s).  ka_to_ms defaults to ka_ms. */
static unsigned long long ka_ms = 25000, ka_to_ms = 25000;
static unsigned long long ka_deadline = 0;
static int ka_wait = 0;               /* a ping is outstanding, awaiting its 81 */
void ss_set_ka(unsigned long long ping_ms, unsigned long long pong_ms)
{
    ka_ms = ping_ms;
    ka_to_ms = pong_ms ? pong_ms : (ping_ms ? ping_ms : 0);
}

#define POLL_MAX 2048
static int ss_pump(void *ctx)
{
 int spins=0,i,lp_n=0;
 if(ka_ms) ka_deadline = now_ms() + ka_ms;
 for(;;){
  /* keepalive: answer the deadline before anything else, so the check runs even when
     no peer byte ever arrives (that is exactly the failure this detects). */
  if(ka_ms){
    unsigned long long n=now_ms();
    if(ka_wait){
      if(n>=ka_deadline){ SLOG("ka: no pong within %u ms: ending session",(unsigned)ka_to_ms); return -1; }
    } else if(n>=ka_deadline){
      pn=0; w_u8(80); w_str("ping"); w_bool(1);
      if(pk_send(ctx)){ SLOG("ka: ping send failed"); return -1; }
      ka_wait=1; ka_deadline = n + ka_to_ms;
      SLOG("ka: ping sent, reply due in %u ms",(unsigned)ka_to_ms);
    }
  }
  /* Wake on peer data OR on any dialed target fd becoming readable.  Never
     enter pk_recv unless the TLS layer actually holds bytes (kernel fd
     readable, or the mbedtls input buffer is non-empty): a silent keep-alive
     target must not starve the pump, and a select timeout must not block
     inside pk_recv.  pump_round drains whatever became readable. */
  { fd_set1 rs, ws; tv1 tv; int k,tlswake=0,wswake=0,sr;
    rs.fd_count=0; ws.fd_count=0;
    if(tls_fd>=0) rs.fd_array[rs.fd_count++]=(unsigned long long)tls_fd;
    /* Window-stalled channels (pend full, no peer credit) are EXCLUDED from
       the select set: their target stays readable (kernel buffer we refuse to
       drain), which would spin the pump at ~66k select/s - a syscall storm
       that starves the server's keepalive path (missed pings -> session death
       at 125s) and burns the beacon's CPU. rx93 reopens the window; the next
       pump_round re-adds the fd once pend/win allow progress. */
    for(k=0;k<CH_N&&rs.fd_count<64;k++) if(chs[k].used&&chs[k].fd>=0&&chs[k].stage==6&&!chs[k].eof_sent&&!chs[k].wait_eof&&(chs[k].pendn<PEND_N||chs[k].win>0)) rs.fd_array[rs.fd_count++]=(unsigned long long)chs[k].fd;
    for(k=0;k<CH_N&&rs.fd_count<64;k++) if(chs[k].used&&chs[k].stage==7){ int j; for(j=0;j<4&&rs.fd_count<64;j++) if(chs[k].ufd[j]>=0) rs.fd_array[rs.fd_count++]=(unsigned long long)chs[k].ufd[j]; }
    /* Outbox frame queued: watch tls_fd for WRITABILITY and drain it, so a
       parked t=94 never blocks the read side. */
    if(ws_outbox_pending()&&tls_fd>=0) ws.fd_array[ws.fd_count++]=(unsigned long long)tls_fd;
    tv.sec=1; tv.usec=0;
    sr=select(0,&rs,&ws,0,&tv); (void)sr;
    if(sr<=0||(lp_n&1023)==0) SLOG("sel sr=%d n=%d lp=%d",sr,(int)rs.fd_count,lp_n);
    if(sr<0){ SLOG("select err=%d n=%d",WSAGetLastError(),(int)rs.fd_count); }
    for(k=0;k<(int)rs.fd_count;k++) if(tls_fd>=0&&(int)rs.fd_array[k]==tls_fd) tlswake=1;
    for(k=0;k<(int)ws.fd_count;k++) if(tls_fd>=0&&(int)ws.fd_array[k]==tls_fd) wswake=1;
    if(wswake){ int f=ws_outbox_flush(ctx); if(f<0){ DM(9019); SLOG("pump: outbox flush fail"); return -1; } }
    if(tlswake){ static unsigned twc=0; if((twc++&255u)==0) SLOG("tlswake n=%u sr=%d",(unsigned)twc,sr); }
    if(!tlswake&&sn==so&&!tls_buffered(ctx)){
      if(pump_round(ctx)){ DM(9018); SLOG("pump: pump_round fail"); return -1; }
      continue;
    }
  }
  { int pr=pk_recv(ctx); if(pr){ DM(9011); SLOG("pump: pk_recv rc=%d",pr); for(i=0;i<CH_N;i++) if(chs[i].used) ch_drop(chs+i); return 0; } }
  if(rn<1){ DM(9015); SLOG("pump: empty packet"); return -1; }
  { int t=(int)rpl[0];
    lp_n++; if(lp_n<300) SLOG("loop %d t=%d len=%d",(int)lp_n,t,(int)rn); if(lp_n==2040) SLOG("loop cap");
    if(t==21){ st_r=1; spins=0; }
    else if(t==20){ if(do_rekey(ctx,rpl,rn)){ DM(9021); SLOG("pump: rekey fail"); return -1; } }
    else if(t==2||t==3||t==4){ spins=0; }
    else if(t==1){ DM(9014); SLOG("peer disconnect"); for(i=0;i<CH_N;i++) if(chs[i].used) ch_drop(chs+i); return 0; }
    else if(t==80){ { rp=1; { const char *nm=rd_str(); uint8_t wr=(rp<rn)?rpl[rp++]:0; SLOG("ping rx nm=%s wr=%d lp=%d",nm?nm:"(fail)",(int)wr,lp_n); if(nm&&teq(nm,"ping")){ DM(9010); if(wr){ pn=0; w_u8(81); w_raw("pong",4); if(pk_send(ctx)){ DM(9016); return -1; } } DM(9020); } } } spins=0; }
    else if(t==81){
      /* REQUEST_SUCCESS: the reply to our keepalive ping.  chisel's server answers with
         the raw payload "pong" (Request.Reply(true, []byte("pong")) - NOT a length-prefixed
         string), and Go's own keepAlivePing accepts an empty body or exactly "pong";
         anything else is a "strange ping response" and ends the session there too. */
      if(ka_wait){ int bl=(int)rn-1; const char *b=(bl>0)?(const char*)(rpl+1):0;
        if(bl==0) { SLOG("ka: pong (empty reply)"); }
        else if(bl==4 && teqp(b,"pong",4)) { SLOG("ka: pong"); }
        else { SLOG("ka: strange ping response (%d bytes): ending session",bl); return -1; }
        ka_wait=0; ka_deadline = now_ms() + ka_ms; }
      }
    else if(t==82){
      /* REQUEST_FAILURE to a global request of ours: the peer does not implement "ping",
         which is a keepalive failure (Go's SendRequest returns the remote error and
         keepAliveLoop closes). */
      if(ka_wait){ const char *m; rp=1; m=rd_str(); SLOG("ka: peer refused ping (%s): ending session",m?m:"no message"); return -1; }
      }
    else if(t==93){ rp=1; { uint32_t id=rd_u32(), add=rd_u32(); { struct channel *c=ch_get(id); if((lp_n&63)==0) SLOG("rx93 id=%u add=%u c=%d win=%u",id,add,c?1:0,c?(unsigned)c->win:0u); if(c) c->win+=add; } } }
    else if(t==90){ DM(9012); if(handle_open(ctx)){ DM(9017); SLOG("pump: handle_open fail"); return -1; } }
    else if(t==94){ if(handle_data(ctx)){ DM(9017); SLOG("pump: handle_data fail"); return -1; } }
    else if(t==96){ rp=1; { uint32_t id=rd_u32(); { struct channel *c=ch_get(id); if(c){ SLOG("peer eof channel %u",id); if(c->fd<0){ C=c; chan_close(ctx); ch_drop(c); } else if(!c->wr_closed){ shutdown(c->fd,1); c->wr_closed=1; } } } } }
    else if(t==97){ rp=1; { uint32_t id=rd_u32(); { struct channel *c=ch_get(id); if(c){ SLOG("peer closed channel %u",id); ch_drop(c); } } } }
    else if(t==92){ rp=1; { uint32_t id=rd_u32(); { struct channel *c=ch_get(id); if(c){ SLOG("channel refused %u",id); ch_drop(c); } } } }
    else { SLOG("unhandled packet %d len=%d",t,(int)rn); }
  }
  if(pump_round(ctx)){ DM(9018); SLOG("pump: pump_round fail"); return -1; }
  {
   int live=0,i;
      for(i=0;i<CH_N;i++) if(chs[i].used){ live=1; break; }   /* open-but-not-yet-dialed channels stay live */
   if(!live){
    /* long-lived: an exhausted channel set does NOT end the session.
       The server sends a fresh open(90) per tunnel connection; keep
       polling (pinging) until real transport death surfaces. */
    if(!chan_seen){ SLOG("pump: no channels yet, keep polling"); }
    else { SLOG("pump: channels closed, awaiting next tunnel open"); }
   }
  /* Three ways this loop learns the transport died: pk_recv errors, the peer closing
     cleanly (handled above), and our own keepalive ping timing out (the ka block at the
     top of the loop).  Pings go out on the configured interval, never per spin: a
     per-spin ping floods the server's request mux (measured: sessions closed every
     ~27.2 s with no wire error). */
  spins++;
  }
 }
}

/* ---- entry: handshake -> auth -> config -> pump (R:socks remote) ---- */
/* ---- per-session state: a reconnecting client starts a brand-new SSH session,
 *  so the channel table, the newkeys/cipher state, and every wire buffer reset. ---- */
static void ss_reset(void)
{
	int i;
	for(i=0;i<CH_N;i++){ chs[i].used=0; chs[i].fd=-1; chs[i].stage=0; chs[i].sbn=0; chs[i].pendn=0; }
	chan_seen=0;
	st_w=0; st_r=0; seq_w=0; seq_r=0;
	ka_wait=0; ka_deadline=0;
	/* wire buffers stay: the WS upgrade read may already hold the accept line */
}

/* ---- entry: handshake -> auth -> config -> pump (R:socks remote) ----
 * `user`/`pass` are chisel's --auth credentials: the chisel server checks them in its
 * SSH PasswordCallback (server/server.go authUser), which is also how it looks up the
 * per-user remote-address allow list from --authfile.  Returns -2 when userauth is
 * rejected, so the caller can tell a credential problem from a transport problem. */
int ss_run(void *ctx,const char *id,const char *user,const char *pass,int lport,int fd,int ubind,const char *urehost,int ureport)
{
 tls_fd=fd;
 ss_reset();
 if(ss_handshake(ctx)){ SLOG("stage handshake failed"); return -1; }
 if(ss_auth(ctx,user,pass)){ SLOG("stage auth failed user=%s",(user&&user[0])?user:"(empty)"); return -2; }
 if(ss_config(ctx,id,"127.0.0.1",lport,"",0,ubind,urehost,ureport)){ SLOG("stage config failed"); return -1; }
 sock_timeo(tls_fd, 0);   /* handshake phase over: the pump drives reads from select() */
 ws_set_nb();   /* post-handshake: non-blocking outbox sends (see pk_send_nb) */
 return ss_pump(ctx);
}
