# tests/mkpayload.py - write a random payload file and print its sha256, for
# slowapp.py (download integrity) and uplapp.py.
# usage: python tests/mkpayload.py [bytes]     default 20971520 (20 MiB)
import hashlib
import os
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 20971520
d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pub")
os.makedirs(d, exist_ok=True)
p = os.path.join(d, "big.bin")
with open(p, "wb") as f:
    rem = n
    while rem > 0:
        blk = os.urandom(min(1 << 20, rem))
        f.write(blk)
        rem -= len(blk)
h = hashlib.sha256(open(p, "rb").read()).hexdigest()
print("payload %s  %d bytes" % (p, n))
print("sha256  %s" % h)
