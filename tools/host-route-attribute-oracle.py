"""Read-only RTM address/route shape oracle; never requests WireGuard keys."""
import datetime
import json
import os
import socket
import struct

assert os.geteuid() == 0
sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
sock.settimeout(2)
sock.bind((0, 0))
port = sock.getsockname()[0]
observations = []
for sequence, (kind, family, size, reply_type) in enumerate(
        [(22, 2, 8, 20), (22, 10, 8, 20), (26, 2, 12, 24), (26, 10, 12, 24)], 90):
    payload = bytes([family]) + bytes(size - 1)
    sock.sendto(struct.pack("IHHII", 16 + size, kind, 0x301, sequence, port) + payload, (0, 0))
    done = False
    total = 0
    messages = []
    while not done:
        data, peer = sock.recvfrom(65536)
        assert peer[0] == 0
        total += len(data)
        assert total < 1024 * 1024
        while data:
            length, message_type, flags, seq, reply_port = struct.unpack_from("IHHII", data)
            assert 16 <= length <= len(data) and seq == sequence and reply_port in (0, port)
            value = data[16:length]
            if message_type == 3:
                done = True
            elif message_type == 2:
                assert struct.unpack_from("i", value)[0] == 0
            else:
                assert message_type == reply_type and len(value) >= size
                attributes = []
                remaining = value[size:]
                while remaining:
                    assert len(remaining) >= 4
                    nla_length, nla_kind = struct.unpack_from("HH", remaining)
                    assert 4 <= nla_length <= len(remaining)
                    attributes.append({"kind": nla_kind, "value_len": nla_length - 4,
                                       "value_hex": remaining[4:nla_length].hex()})
                    remaining = remaining[(nla_length + 3) & ~3:]
                messages.append({"header_hex": value[:size].hex(), "attributes": attributes,
                                 "message_hex": data[:length].hex()})
            data = data[(length + 3) & ~3:]
    observations.append({"request_type": kind, "family": family, "messages": messages})
print(json.dumps({"observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "read_only": True, "wireguard_queried": False,
                  "observations": observations}, indent=2))
