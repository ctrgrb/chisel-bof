# run on the SERVER machine while the client exposes R:<bind>:127.0.0.1:9053/udp
# exercises: multi-socket, source-port fidelity, same-socket reuse, 1000 B datagram
import socket, sys
bind_port = int(sys.argv[1]) if len(sys.argv) > 1 else 9054
def q(m, sock):
    sock.sendto(m, ("127.0.0.1", bind_port))
    sock.settimeout(8)
    return sock.recvfrom(4096)[0]
s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s2.bind(("127.0.0.1", 9199))
r1 = q(b"DNSQ1", s1);                print("q1:", r1)
r2 = q(b"DNSQ2-srcport9199", s2);    print("q2:", r2)
r3 = q(b"DNSQ3-same-socket", s1);    print("q3:", r3)
r4 = q(b"B" * 1000, s2);             print("q4:", len(r4), r4[:5], r4[-3:])
r5 = q(b"DNSQ5", s2);                print("q5:", r5)
ok = (r1 == b"ECHO:DNSQ1" and r2 == b"ECHO:DNSQ2-srcport9199"
      and r3 == b"ECHO:DNSQ3-same-socket" and len(r4) == 1005 and r5 == b"ECHO:DNSQ5")
print("UDP-TEST", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
