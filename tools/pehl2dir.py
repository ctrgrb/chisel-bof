# PE .reloc rewriter: x64 HIGHLOW (0xa) -> DIR64 (0xb) + histogram audit
#
#   python tools/ext/pehl2dir.py <in.dll> <out.dll>      (out '-' = stdout)
#   python tools/ext/pehl2dir.py --audit <in.dll> ...     (audit only)
#
# binutils-2.30 (C:/Users/Admin/toolchain/mingw64) emits x64 DLL relocations as
# IMAGE_REL_BASED_HIGHLOW, which only patches the LOW 4 bytes of an 8-byte slot.
# Windows' own loader tolerates that because it keeps the image below 4GB; a BOF-PE
# loader that VirtualAllocs a modern x64 heap address needs the high dword too, so
# every absolute pointer comes back truncated and the first indirect call/jump faults.
# DIR64 (0xb) is the canonical x64 type: the 8-byte slot holds the preferred-image
# RVA and the loader adds the relocations delta.  We rewrite the entry type nibble
# only, after proving every affected slot holds an absolute VA inside the image.
#
# .reloc block walk (entries are 2 bytes each): cnt = (bsize-8)//2, block advance
# is (bsize+3)&~3 -- the old walk advanced by bsize//4 and double-counted.
import struct, sys

DIRS = ["Export", "Import", "Resource", "Security", "BaseReloc(legacy)", "BaseReloc",
        "Debug", "Export(old)", "Import(old)", "Resource(old)", "TLS", "Checksum",
        "BoundImport", "DelayImport", "ASM"]


def parse(d):
    lf = struct.unpack_from('<I', d, 0x3c)[0]
    opt = lf + 24
    base = struct.unpack_from('<Q', d, lf + 48)[0]
    size = struct.unpack_from('<I', d, opt + 56)[0]
    nsec = struct.unpack_from('<H', d, lf + 6)[0]
    osz = struct.unpack_from('<H', d, lf + 20)[0]
    tab = opt + osz
    secs = []
    for i in range(nsec):
        o = tab + 40 * i
        name = d[o:o + 8].rstrip(b'\0').decode('ascii', 'ignore')
        vsz, va, rsz, praw = struct.unpack_from('<IIII', d, o + 8)
        secs.append((name, va, vsz, rsz, praw))

    def off(rva):
        for name, va, vsz, rsz, praw in secs:
            if va <= rva < va + vsz:
                return praw + (rva - va) if praw else None
        return None

    def blocks():
        for idx in (4, 5):
            rva, bsz = struct.unpack_from('<II', d, opt + 112 + idx * 8)
            if not bsz:
                continue
            o = off(rva)
            if o is None:
                continue
            while True:
                bva, bsize = struct.unpack_from('<II', d, o)
                if bsize < 8:
                    break
                yield bva, o, bsize
                o += (bsize + 3) & ~3

    return lf, base, size, secs, off, blocks


def audit(d, label):
    lf, base, size, secs, off, blocks = parse(d)
    hist = {}
    slots = []
    for bva, o, bsize in blocks():
        for k in range((bsize - 8) // 2):
            v = struct.unpack_from('<H', d, o + 8 + 2 * k)[0]
            t = v >> 12
            hist[t] = hist.get(t, 0) + 1
            if t:
                slots.append((bva + (v & 0xFFF), t))
    print('%s: file %d base %#x SizeOfImage %#x dc %#x hist %s' %
          (label, len(d), base, size,
           struct.unpack_from('<H', d, parse(d)[0] + 24 + 116)[0], dict(sorted(hist.items()))))
    bad = []
    for rva, t in slots:
        fo = off(rva)
        if fo is None:
            bad.append((rva, t, None))
            continue
        val = struct.unpack_from('<Q', d, fo)[0]
        if not (base <= val < base + size):
            bad.append((rva, t, val))
    print('  %d absolute slots: in-image %d, out-of-image %d' % (len(slots), len(slots) - len(bad), len(bad)))
    for rva, t, val in bad[:8]:
        print('   slot rva %#x type %#x val %s' % (rva, t, hex(val) if val else 'unmapped'))
    return hist, slots


def convert(src, dst):
    with open(src, 'rb') as f:
        d = bytearray(f.read())
    hist, slots = audit(d, 'input')
    done = kept = bad = 0
    for bva, o, bsize in list(parse(d)[5]()):
        for k in range((bsize - 8) // 2):
            eo = o + 8 + 2 * k
            v = struct.unpack_from('<H', d, eo)[0]
            t = v >> 12
            if t == 0xA:
                struct.pack_into('<H', d, eo, (0xB << 12) | (v & 0xFFF))
                done += 1
            elif t == 0xB:
                kept += 1
    audit(d, 'output')
    print('rewrote %d HIGHLOW -> DIR64, %d already DIR64' % (done, kept), file=sys.stderr)
    if dst == '-':
        sys.stdout.buffer.write(d)
        sys.stdout.buffer.flush()
    else:
        with open(dst, 'wb') as f:
            f.write(d)
        print('wrote', dst, len(d), 'bytes', file=sys.stderr)


args = sys.argv[1:]
if args[:1] == ['--audit']:
    for p in args[1:]:
        with open(p, 'rb') as f:
            audit(f.read(), p)
else:
    convert(args[0], args[1])
