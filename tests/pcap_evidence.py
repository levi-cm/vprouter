#!/usr/bin/env python3
"""Count packets and exact test markers in a classic pcap capture."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def inspect(path: Path, markers: list[bytes]):
    digest = hashlib.sha256()
    counts = {marker.decode("ascii"): 0 for marker in markers}
    packets = 0
    first = last = None
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError("not a classic pcap file")
        digest.update(header)
        endian, resolution = MAGIC[header[:4]]
        _, _, _, _, snaplen, _ = struct.unpack(endian + "HHIIII", header[4:])
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("truncated pcap record header")
            digest.update(record)
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > snaplen or captured > original or fraction >= resolution:
                raise ValueError("invalid pcap record")
            packet = stream.read(captured)
            if len(packet) != captured:
                raise ValueError("truncated pcap packet")
            digest.update(packet)
            moment = seconds + fraction / resolution
            if first is None:
                first = moment
            last = moment
            packets += 1
            for marker in markers:
                counts[marker.decode("ascii")] += packet.count(marker)
    return {
        "file": path.name,
        "sha256": digest.hexdigest(),
        "packets": packets,
        "first_utc": datetime.fromtimestamp(first, timezone.utc).isoformat() if first else None,
        "last_utc": datetime.fromtimestamp(last, timezone.utc).isoformat() if last else None,
        "markers": counts,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("markers", nargs="*", help="exact ASCII payload markers")
    args = parser.parse_args()
    print(json.dumps(inspect(args.pcap, [marker.encode("ascii") for marker in args.markers]), indent=2))
