import socket
import struct
import textwrap
import time

devicesIPV = {}
devicesARP = {} # MAC, IP, first_con, last_con, reply_count, request_count
request_window = {} # IP, timestamp, count
threshold = 50
clean = 60

def main():
    global last_clean
    last_clean=time.time()
    # CREATE A RAW SOCKET
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        now = time.time() #FOR CLEANING
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # IPV4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\t- IPv4 Packet:')
            print(f'\t\t- Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\t- Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\t\t- ICMP Packet:')
                print(f'\t\t\t- Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print('\t\t\t- Data:')
                print(format_multi_line('\t\t\t\t', data))

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,
                 flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print('\t\t- TCP Segment:')
                print(f'\t\t\t- Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'\t\t\t- Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'\t\t\t- Flags:')
                print(f'\t\t\t\t- URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print('\t\t\t- Data:')
                print(format_multi_line('\t\t\t\t', data))

            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('\t\t- UDP Segment:')
                print(f'\t\t\t- Source Port: {src_port}, Destination Port: {dest_port}, Size: {size}')
                print('\t\t\t- Data:')
                print(format_multi_line('\t\t\t\t', data))

            else:
                print('\t\t- Other IPv4 Protocol:')
                print(format_multi_line('\t\t\t', data))
        
        # ARP
        elif eth_proto == 0x0806:
            opcode, sender_mac, sender_ip, target_mac, target_ip = arp_packet(data)
            add_update(opcode, sender_ip, sender_mac)
            check_time_request(sender_ip)
            arp_spoofing(devicesARP, sender_ip, sender_mac)
        
        if now - last_clean >= clean:
            clean_inactive_devices(devicesARP)
            last_clean = now
    

        

            


# HELPER FUNCTIONS
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# FUNCTION TO FORMAT MAC ADDRESS
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# UNPACK IPV4 PACKET
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# FUNCTION TO FORMAT IPV4 ADDRESS
def ipv4(addr):
    return '.'.join(map(str, addr))

# UNPACK ICMP PACKET
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# UNPACK TCP PACKET
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# UNPACK UDP PACKET
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# UNPACK ARP PACKET
def arp_packet(data):
    opCode, sender_MAC, sender_IP, target_MAC, target_IP = struct.unpack('! 6x H 6s 6s 4s 4s',data[:28])
    sender_MAC=get_mac_addr(sender_MAC)
    sender_IP=ipv4_packet(sender_IP)
    target_MAC=get_mac_addr(target_MAC)
    target_IP=ipv4_packet(target_IP)
    opCode = 'REQUEST' if opCode == 1 else 'REPLY' if opCode == 2 else 'UNKNOWN'

    return opCode, sender_MAC, sender_IP, target_MAC, target_IP

# ADD/UPDATE DEVICES ARP
def add_update(opcode, sender_ip, sender_mac):
            # REPLY and REQUEST COUNT
            if sender_ip not in devicesARP:
                print(f"New con: {sender_ip}")
                devicesARP[sender_ip] = {
                    'mac': sender_mac,
                    'first_connection': time.time(),
                    'last_connection': time.time(),
                    'reply_count': 0,
                    'request_count': 0
                }

            if opcode == "REQUEST":
                devicesARP[sender_ip]['request_count'] += 1

            elif opcode == "REPLY":
                devicesARP[sender_ip]['reply_count'] += 1

# CHECK TIME REQUEST
def check_time_request(sender_ip):
        time_dif= time.time() - devicesARP[sender_ip]['first_connection']
        if time_dif > 0:
            rpm = devicesARP[sender_ip]['request_count'] / (time_dif / 60)
            if rpm > threshold:
                print(f"+50 request per minute from {devicesARP[sender_ip]}")

# CLEAN TTL
def clean_inactive_devices(timeout=300):
    current_time = time.time()
    
    for ip in list(devicesARP.keys()):
        if current_time - devicesARP[ip]['last_connection'] > timeout:
            print(f"Removing inactive device: {ip}")
            del devicesARP[ip]

# ARP SPOOFING
def arp_spoofing(sender_ip, sender_mac):
    if sender_ip in devicesARP and devicesARP[sender_ip]['mac'] != sender_mac:
        print(f"ARP SPOOFING: {sender_ip} <> old mac:{devicesARP[sender_ip]['mac']}, new mac:{sender_mac}")

# IP SPOOFING
def ip_spoofing(sender_ip, sender_mac):
    if sender_ip not in devicesARP:
        return




# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == '__main__':
    main()
