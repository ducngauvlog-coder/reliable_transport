import argparse
import struct
import sys
import zlib
from socket import socket, AF_INET, SOCK_DGRAM

HEADER_FORMAT = "!IIII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

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
    parser.add_argument("receiver_ip", help="IP address to listen on")
    parser.add_argument("receiver_port", type=int, help="Port to listen on")
    parser.add_argument("window_size", type=int, help="Window size")
    args = parser.parse_args()

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((args.receiver_ip, args.receiver_port))

    connection_active = False
    expected_seq = 0
    buffer = {}

    while True:
        raw_bytes, sender_addr = sock.recvfrom(2048)
        pkt_type, seq_num, length, data = parse_packet(raw_bytes)

        if pkt_type is None:
            continue

        if pkt_type == TYPE_START:
            if not connection_active:
                connection_active = True
                expected_seq = 1
                ack_pkt = make_packet(TYPE_ACK, expected_seq)
                sock.sendto(ack_pkt, sender_addr)
            continue

        if not connection_active:
            continue

        if pkt_type == TYPE_DATA:
            if seq_num >= expected_seq + args.window_size:
                continue

            if seq_num < expected_seq:
                ack_pkt = make_packet(TYPE_ACK, expected_seq)
                sock.sendto(ack_pkt, sender_addr)
                continue

            buffer[seq_num] = data

            while expected_seq in buffer:
                chunk = buffer.pop(expected_seq)
                sys.stdout.buffer.write(chunk)
                sys.stdout.flush()
                expected_seq += 1

            ack_pkt = make_packet(TYPE_ACK, expected_seq)
            sock.sendto(ack_pkt, sender_addr)

        elif pkt_type == TYPE_END:
            ack_pkt = make_packet(TYPE_ACK, seq_num)
            sock.sendto(ack_pkt, sender_addr)
            break

    sock.close()

if __name__ == "__main__":
    main()
