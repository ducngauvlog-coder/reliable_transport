import argparse
import select
import struct
import sys
import time
import zlib
from socket import socket, AF_INET, SOCK_DGRAM

HEADER_FORMAT = "!IIII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
CHUNK_SIZE = 1450

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

def make_packet(pkt_type, seq_num, data=b""):
    length = len(data)
    checksum = zlib.crc32(data) & 0xffffffff
    header = struct.pack(HEADER_FORMAT, pkt_type, seq_num, length, checksum)
    return header + data

def parse_packet(raw_bytes):
    if len(raw_bytes) < HEADER_SIZE:
        return None, None, None, None
    pkt_type, seq_num, length, checksum = struct.unpack(HEADER_FORMAT, raw_bytes[:HEADER_SIZE])
    data = raw_bytes[HEADER_SIZE:HEADER_SIZE + length]
    if (zlib.crc32(data) & 0xffffffff) != checksum:
        return None, None, None, None
    return pkt_type, seq_num, length, data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="IP address of receiver")
    parser.add_argument("receiver_port", type=int, help="Port of receiver")
    parser.add_argument("window_size", type=int, help="Window size")
    args = parser.parse_args()

    target = (args.receiver_ip, args.receiver_port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.setblocking(False)

    full_data = sys.stdin.buffer.read()
    chunks = [full_data[i:i + CHUNK_SIZE] for i in range(0, len(full_data), CHUNK_SIZE)]
    packets = [None]
    for i, chunk in enumerate(chunks, start=1):
        packets.append(make_packet(TYPE_DATA, i, chunk))
    total_packets = len(chunks)

    start_pkt = make_packet(TYPE_START, 0)
    while True:
        sock.sendto(start_pkt, target)
        ready = select.select([sock], [], [], 0.5)
        if ready[0]:
            try:
                raw_bytes, _ = sock.recvfrom(2048)
                pkt_type, seq_num, _, _ = parse_packet(raw_bytes)
                if pkt_type == TYPE_ACK and seq_num == 1:
                    break
            except:
                pass

    base = 1
    next_seq = 1
    timer_start = None
    acked = {i: False for i in range(1, total_packets + 1)}

    while base <= total_packets:
        while next_seq < base + args.window_size and next_seq <= total_packets:
            sock.sendto(packets[next_seq], target)
            if timer_start is None:
                timer_start = time.time()
            next_seq += 1

        ready = select.select([sock], [], [], 0.01)
        if ready[0]:
            try:
                raw_bytes, _ = sock.recvfrom(2048)
                pkt_type, seq_num, _, _ = parse_packet(raw_bytes)
                if pkt_type == TYPE_ACK and seq_num in acked:
                    acked[seq_num] = True
                    old_base = base
                    while base <= total_packets and acked[base]:
                        base += 1
                    if base != old_base:
                        if base < next_seq:
                            timer_start = time.time()
                        else:
                            timer_start = None
            except:
                pass

        if timer_start is not None and (time.time() - timer_start >= 0.5):
            for seq in range(base, next_seq):
                if not acked[seq]:
                    sock.sendto(packets[seq], target)
            timer_start = time.time()

    end_pkt = make_packet(TYPE_END, total_packets + 1)
    end_time = time.time()
    sock.sendto(end_pkt, target)

    while time.time() - end_time < 0.5:
        ready = select.select([sock], [], [], 0.05)
        if ready[0]:
            try:
                raw_bytes, _ = sock.recvfrom(2048)
                pkt_type, _, _, _ = parse_packet(raw_bytes)
                if pkt_type == TYPE_ACK:
                    break
            except:
                pass

    sock.close()

if __name__ == "__main__":
    main()
