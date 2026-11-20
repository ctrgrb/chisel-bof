#!/usr/bin/env python3
r"""tests/packedargs.py [path\to\chiselbof.dll]

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
  hang (watchdog)                   -> the run is still going: correct for an UNBOUNDED run, and the
                                       proof that per-run flags did not leak from an earlier case

A dropped or mis-parsed record shows up as a *hang* (unlimited retries against the closed port),
which is what the old NUL-driven record copy did to a `b`-type record; each case therefore runs
under a watchdog so the suite is bounded either way.

Record forms covered: Cobalt-Strike header (`u32` = size of remainder), Outflank header (`u32` =
total incl. header), no header; `z` (NUL inside), `b` (no NUL), and `Z` (UTF-16LE, collapsed by the
payload's wide detection). Argument forms: one record per argument, and ONE record holding a whole
command line (split by the payload, where dashed flag spellings are legal again because the C2
never sees a token starting with '-').
"""
import ctypes, os, struct, sys, threading, time

DLL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "build", "chiselbof.dll")
DEAD = "http://127.0.0.1:9"          # closed port: connect is refused instantly
BOUNDS = ["max-retry-count", "1", "connect-timeout", "1s"]


def narrow(args, nul=True):
    out = b""
    for a in args:
        b = a.encode() + (b"\0" if nul else b"")
        out += struct.pack("<I", len(b)) + b
    return out


def wide(s):
    """one UTF-16LE 'Z' record (terminator is a 16-bit NUL)"""
    b = s.encode("utf-16-le") + b"\0\0"
    return struct.pack("<I", len(b)) + b


def pack(body, form="cs"):
    if form == "cs":        # u32 = size of the remainder
        return struct.pack("<I", len(body)) + body
    if form == "olf":       # u32 = total, header included
        return struct.pack("<I", len(body) + 4) + body
    return body             # no header at all


def main():
    if not os.path.exists(DLL):
        print("not found:", DLL)
        return 2
    dll = ctypes.CDLL(DLL)
    dll.go.argtypes = [ctypes.c_char_p, ctypes.c_int]
    dll.go.restype = ctypes.c_int

    def call(buf):
        box = [None]
        t0 = time.time()
        def run():
            b = ctypes.create_string_buffer(buf, len(buf))
            box[0] = dll.go(b, len(buf))
        th = threading.Thread(target=run, daemon=True)
        th.start(); th.join(15)
        rc, dt = box[0], time.time() - t0
        return ("hang" if rc is None else rc), dt

    line = lambda s: pack(narrow([s]), "cs")          # ONE record: a whole command line
    b = " ".join([DEAD, "R:1080:socks"] + BOUNDS)

    cases = [
        # record forms, one argument per record
        ("cs header, z records, dash-free flags",
         pack(narrow([DEAD, "R:1080:socks"] + BOUNDS), "cs"), 1),
        ("Outflank header form",
         pack(narrow([DEAD, "R:1080:socks"] + BOUNDS), "olf"), 1),
        ("b records (no NUL) for the flag tokens",
         pack(narrow([DEAD, "R:1080:socks"]) + narrow(BOUNDS, nul=False)), 1),
        ("24 records (at the cap) runs",
         pack(narrow([DEAD, "R:1080:socks", "auth", "u:p"] + BOUNDS +
                     ["--ver", "1.12.1"] * 8), "olf"), 1),
        ("26 records (over the cap) refuses",
         pack(narrow([DEAD, "R:1080:socks", "auth", "u:p"] + BOUNDS +
                     ["--ver", "1.12.1"] * 9), "olf"), 6),
        ("bad duration via a dash-free name",
         pack(narrow([DEAD, "R:1080:socks", "keepalive", "99zz"]), "cs"), 7),
        # one record = one command line, split by the payload
        ("single record, dash-free command line", line(b), 1),
        ("single record, DASHED command line (dashes legal here)",
         line(" ".join([DEAD, "R:1080:socks", "--max-retry-count", "1",
                        "--connect-timeout", "1s"])), 1),
        ("single record, quoted value keeps its space",
         line('%s R:1080:socks keepalive "99 zz"' % DEAD), 7),
        ("single record, same value unquoted (two tokens, no error)",
         line("%s R:1080:socks keepalive 99 zz max-retry-count 1 connect-timeout 1s" % DEAD), 1),
        ("single record, unterminated quote refuses",
         line('%s R:1080:socks keepalive "99zz' % DEAD), 6),
        ("single record, 25 tokens (over the cap) refuses",
         line(" ".join([DEAD, "R:1080:socks"] + ["--ver 1.12.1"] * 11 + BOUNDS)), 6),
        # wide ('Z' UTF-16LE) records: the assertions must fail if the payload did NOT decode,
        # which is why they hang or return slowly rather than merely returning the same code.
        ("Z record command line, no bounds -> retries forever",
         pack(wide("%s R:1080:socks" % DEAD)), "hang"),
        ("Z record holds a flag NAME, z records the rest",
         pack(narrow([DEAD, "R:1080:socks"]) + wide("max-retry-count") +
              narrow(["1", "connect-timeout", "1s"])), 1),
        # Per-run state must not survive a go() call: a beacon may run the payload twice in one
        # process, and an inherited --max-retry-count would bound this run.  "hang" IS the assertion.
        ("run #2 does not inherit run #1's flags (unbounded -> hangs)",
         pack(narrow([DEAD, "R:1080:socks"])), "hang"),
        # The backoff must be REAL, not merely printed: Winsock rejects the NULL-set select sleep
        # (returns WSAEINVAL at once), which used to make every redial immediate.  3 attempts
        # (connect-timeout 1s each) plus 2 sleeps of 1s cannot finish inside 1.8s.
        ("backoff sleeps for real (3 attempts x 1s dial + 2 x 1s wait)",
         pack(narrow([DEAD, "R:1080:socks", "max-retry-count", "3", "connect-timeout", "1s",
                      "min-retry-interval", "1s", "max-retry-interval", "1s"])), 1, 1.8),
    ]

    bad = 0
    for case in cases:
        name, buf, want = case[0], case[1], case[2]
        min_dt = case[3] if len(case) > 3 else 0.0
        rc, dt = call(buf)
        ok = (rc == want) and (dt >= min_dt)
        print("  %-52s rc=%-5s want=%-5s %5.2fs(min %4.2fs) %-4.4s" % (name, str(rc), str(want), dt, min_dt, "PASS" if ok else "FAIL"))
        if not ok:
            bad += 1
    print("PACKED-ARGS " + ("PASS" if bad == 0 else "FAIL (%d)" % bad))
    # force the exit: a case that hangs leaves a retrying payload thread inside the DLL
    os._exit(0 if bad == 0 else 1)


if __name__ == "__main__":
    main()
