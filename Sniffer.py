import socket
import struct
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'dest_mac': get_mac_addr(dest_mac),
        'src_mac': get_mac_addr(src_mac),
        'protocol': socket.htons(proto),
        'data': data[14:]
    }

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return {
        'version': version_header_length >> 4,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'src': socket.inet_ntoa(src),
        'target': socket.inet_ntoa(target),
        'data': data[header_length:]
    }

# Main loop to capture packets
print("Sniffing packets... (Press Ctrl+C to stop)\n")
try:
    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth = ethernet_frame(raw_data)
        print(f"\nEthernet Frame:")
        print(f"  Source: {eth['src_mac']}, Destination: {eth['dest_mac']}, Protocol: {eth['protocol']}")

        if eth['protocol'] == 8:  # IPv4
            ipv4 = ipv4_packet(eth['data'])
            print(f"  IPv4 Packet:")
            print(f"    From: {ipv4['src']} -> To: {ipv4['target']} | Protocol: {ipv4['protocol']}")
except KeyboardInterrupt:
    print("\nExiting packet sniffer.")
