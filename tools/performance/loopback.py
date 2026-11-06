"""TCP/UDP/DNS-like localhost HARNESS SELF-TEST ONLY, never router evidence."""
import argparse
import json
import socket
import struct
import time


class SelfTestFailure(ValueError):
    pass


def self_test(iterations=3):
    if type(iterations) is not int or not 1<=iterations<=20:raise ValueError('iteration_bound')
    deadline=time.monotonic()+2
    def check(ok):
        if not ok or time.monotonic()>=deadline:raise SelfTestFailure('loopback_self_test_failed')
    def receive(sock,size):
        result=b''
        while len(result)<size:
            part=sock.recv(size-len(result));check(bool(part));result+=part
        return result
    counts=dict(tcp=0,udp=0,dns_like=0)
    # All addresses are literal IPv4 loopback. No resolver, user-supplied target,
    # namespace, privilege, external endpoint, or existing service is used.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.settimeout(.1);server.bind(('127.0.0.1',0));server.listen(1)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
            client.settimeout(.1);client.connect(server.getsockname())
            peer,address=server.accept()
            with peer:
                peer.settimeout(.1);check(address[0]=='127.0.0.1')
                for index in range(iterations):
                    payload=struct.pack('!I',index)+b'local-harness'*8
                    client.sendall(payload);got=receive(peer,len(payload));check(got==payload)
                    peer.sendall(got);check(receive(client,len(payload))==payload);counts['tcp']+=1
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        server.settimeout(.1);client.settimeout(.1)
        server.bind(('127.0.0.1',0));client.bind(('127.0.0.1',0))
        for index in range(iterations):
            for kind in ('udp','dns_like'):
                question=b'\x07offline\x04test\x00\x00\x01\x00\x01'
                payload=struct.pack('!HHHHHH',index,0x0100,1,0,0,0)+question if kind=='dns_like' else b'local-udp'+struct.pack('!I',index)
                check(client.sendto(payload,server.getsockname())==len(payload))
                got,address=server.recvfrom(4096);check(got==payload and address==client.getsockname())
                if kind=='dns_like':
                    answer=struct.pack('!HHHHHH',index,0x8180,1,1,0,0)+question+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01'
                else:answer=got
                check(server.sendto(answer,address)==len(answer))
                reply,sender=client.recvfrom(4096);check(reply==answer and sender==server.getsockname())
                counts[kind]+=1
    check(True)
    return dict(schema=1,purpose='harness_self_test',performance_evidence=False,release_ready=False,
                status='SELF_TEST_PASS',protocols=counts,
                scope='127.0.0.1 ephemeral sockets only; no product throughput or latency evidence')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--iterations',type=int,default=3)
    args=parser.parse_args()
    try:result=self_test(args.iterations)
    except (ValueError,OSError):
        print(json.dumps(dict(status='SELF_TEST_FAIL',purpose='harness_self_test',performance_evidence=False,release_ready=False)))
        return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
