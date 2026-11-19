#!/usr/bin/env python3
r"""tests/packedargs.py [path\\to\\chiselbof.dll]

Directly drives the DLL export `go(args, len)` with hand-built beacon-argument buffers, so the
packed-argument contract is testable without a server, without a beacon and without a C2 CLI.
This is the layer OST's `exec_bof <types><args>` writes, and the layer that used to truncate a
long list silently.

    python tests\packedargs.py build\chiselbof.dll

Every case ends by itself (remotes point at a closed loopback port and the run is bounded with
`max-retry-count 1` + `connect-timeout 1s`), and the payload's return code is the assertion:

  1  the dial budget was exhausted  -> the flags WERE parsed and applied
  6  refused to start               -> malformed / over-long packed args
  7  bad flag value                 -> the flag was found, its value was not a duration

A dropped or mis-parsed record shows up as a *hang* (unlimited retries against the closed port),
which is what the old NUL-driven record copy did to a `b`-type record.

Cases:
  1. CS header form (u32 = size of remainder), all `z` records, dash-free flag names
  2. Outflank header form (u32 = total incl. header)
  3. `b` records (length-prefixed bytes, NO NUL inside) for the flag tokens - the copy must be
     length-driven, and the flag must still be applied (returns 1, not a hang)
  4. 24 records: at the cap, must run (return 1)
  5. 26 records: over the cap, must refuse with 6 - no dial, no session, no truncation
  6. `keepalive 99zz` -> 7, i.e. a dash-free name still reaches the duration parser
"""
import ctypes, os, socket, struct, sys, time

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "build", "chiselbof.dll")
DEAD = "http://127.0.0.1:9"          # closed port: connect is refused instantly


def records(args, nul=True):
    """beacon 'z' records ([u32 len][bytes+NUL]) or 'b' records (no NUL)"""
    out = b""
    for a in args:
        b = a.encode()
        b += b"\0" if nul else b""
        out += struct.pack("<I", len(b)) + b
    return out


def pack(args, form="cs", nul=True):
    body = records(args, nul)
    if form == "cs":        # u32 = size of the remainder
        return struct.pack("<I", len(body)) + body
    if form == "olf":       # u32 = total, header included
        return struct.pack("<I", len(body) + 4) + body
    return body             # no header at all


def call(dll, buf):
    buf = ctypes.create_string_buffer(buf, len(buf))
    t0 = time.time()
    rc = dll.go(buf, len(buf.raw))
    return rc, time.time() - t0


def main():
    if not os.path.exists(DLL):
        print("not found:", DLL)
        return 2
    dll = ctypes.CDLL(DLL)
    dll.go.argtypes = [ctypes.c_char_p, ctypes.c_int]
    dll.go.restype = ctypes.c_int

    bounded = ["max-retry-count", "1", "connect-timeout", "1s"]
    cases = [
        ("cs header, z records, dash-free flags",
         pack([DEAD, "R:1080:socks"] + bounded, "cs"), 1),
        ("Outflank header form",
         pack([DEAD, "R:1080:socks"] + bounded, "olf"), 1),
        ("b records (no NUL) for the flag tokens",
         records([DEAD, "R:1080:socks"]) +
         records(bounded, nul=False), 1),
        ("24 records (at the cap) runs",
         pack([DEAD, "R:1080:socks", "auth", "u:p"] + bounded +
              ["--ver", "1.12.1"] * 8, "olf"), 1),
        ("26 records (over the cap) refuses",
         pack([DEAD, "R:1080:socks", "auth", "u:p"] + bounded +
              ["--ver", "1.12.1"] * 9, "olf"), 6),
        ("bad duration via a dash-free name",
         pack([DEAD, "R:1080:socks", "keepalive", "99zz"], "cs"), 7),
    ]

    bad = 0
    for name, buf, want in cases:
        rc, dt = call(dll, buf)
        ok = (rc == want)
        if rc == 0:      # a session that should never happen against a closed port
            ok = False
        print("  %-42s rc=%-3d want=%-3d %-4.4s %.2fs" % (name, rc, want, "PASS" if ok else "FAIL", dt))
        if not ok:
            bad += 1
    print("PACKED-ARGS " + ("PASS" if bad == 0 else "FAIL (%d)" % bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
