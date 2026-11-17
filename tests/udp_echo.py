# run on the SERVER machine: a UDP echo target the /udp remote dials
import socket, sys
port = int(sys.argv[1]) if len(sys.argv) > 1 else 9053
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
print("udp echo on 127.0.0.1:%d" % port, flush=True)
while True:
    d, a = s.recvfrom(65535)
    s.sendto(b"ECHO:" + d, a)
