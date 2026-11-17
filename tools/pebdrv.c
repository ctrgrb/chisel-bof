/* pebdrv.c - BOF-PE smoke loader: loads the linked PE, resolves the exported
   entry, and calls go(const char* data, int len) with beacon-packed args
   (NetSPI/BOF-PE convention; layout per tools/ext/coff/beacon_compatibility.c
   WriteString + loader/common/standalone.cpp:51-64).  The buffer carries NO
   size header - loader/main.cpp:104 passes args.data(), args.length() - unlike
   classic CS COFF beacons, which prefix [u32 = size of remainder].
   Every CLI arg after the DLL path is packed as a 'z' string, so the
   argument format is "zz" for <url> <remote>.
   usage: pebdrv.exe <chiselpe.dll> <url> <remote...>  */
#include <stdio.h>
#include <windows.h>

static unsigned char pkt[4096];

static void put32(unsigned char *p, unsigned v)
{ p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }

int main(int argc, char **argv)
{
    int i, k, body, total, rc;
    if(argc < 3){ printf("usage: pebdrv.exe <dll> <url> <remote...>\n"); return 7; }
    HMODULE m = LoadLibraryEx(argv[1], 0, 0);
    if(!m){ printf("load fail err=%lu\n", (unsigned long)GetLastError()); return 9; }
    printf("loaded @%p\n", (void*)m);
    int (*go)(const char*, int);
    go = (int (*)(const char*, int))GetProcAddress(m, "go");
    if(!go){ printf("no 'go' export\n"); return 8; }
    printf("go=%p\n", (void*)go);
    body = 0;
    for(i=2;i<argc;i++){
        int l = 0; while(argv[i][l]) l++; l++;   /* payload length incl. NUL */
        if(body + 4 + l > (int)sizeof pkt){ printf("args too large\n"); return 7; }
        put32(pkt + body, (unsigned)l);
        for(k=0;k<l;k++) pkt[body + 4 + k] = (unsigned char)(k < l-1 ? argv[i][k] : 0);
        body += 4 + l;
    }
    total = body;

    printf("packed %d bytes, format", total);
    for(i=2;i<argc;i++) printf(" z");
    printf(":");
    for(i=0;i<total;i++) printf(" %02x", pkt[i]);
    printf("\n");
    fflush(stdout);

    rc = go((const char*)pkt, total);
    printf("go rc=%d\n", rc);
    return 0;
}
