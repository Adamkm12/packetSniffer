import socket
import struct
import time

# ══════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════
ARP_REQUEST_THRESHOLD = 50  # requests per minute
TTL = 300                   # inactive seconds
CLEAN_INTERVAL = 60         # clean every 60 sec


devices = {}

# Example:
# devices[ip] = {
#     'mac': 'AA:BB:CC:DD:EE:FF',
#     'first_seen': timestamp,
#     'last_seen': timestamp,
#     'arp_requests': 0,
#     'arp_replies': 0,
#     'spoofing_count': 0
# }

# ══════════════════════════════════════════
# TIMERS
# ══════════════════════════════════════════
last_clean = time.time()


def main():
    global last_clean
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        now = time.time()
        
        # ═══════════════════════════════════════════════
        # IPv4
        # ═══════════════════════════════════════════════
        if eth_proto == 8:
            (version, header_length, ttl, proto, src_ip, dst_ip, data) = ipv4_packet(data)
            
            update_device(src_ip, src_mac, 'ipv4')
            check_ip_spoofing(src_ip, src_mac)
            
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                devices[sender_ip]['icmp_count'] += 1
                # TODO: Aquí añadirás ICMP flood detection
            
            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, 
                 flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                # TODO: Aquí añadirás SYN flood detection
            
            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
        
        # ═══════════════════════════════════════════════
        # ARP
        # ═══════════════════════════════════════════════
        elif eth_proto == 0x0806:
            opcode, sender_mac, sender_ip, target_mac, target_ip = arp_packet(data)
            
            update_device(sender_ip, sender_mac, 'arp')
            
            if sender_ip in devices:
                if opcode == "REQUEST":
                    devices[sender_ip]['arp_requests'] += 1
                elif opcode == "REPLY":
                    devices[sender_ip]['arp_replies'] += 1
            
            check_arp_flood(sender_ip)
        
        # ═══════════════════════════════════════════════
        # LIMPIEZA PERIÓDICA
        # ═══════════════════════════════════════════════
        if now - last_clean >= CLEAN_INTERVAL:
            clean_inactive_devices()
            last_clean = now


# FUNCIONES DE ACTUALIZACIÓN
def update_device(ip, mac, source='ipv4'):
    """Actualiza o crea entrada de dispositivo"""
    now = time.time()
    
    if ip not in devices:
        devices[ip] = {
            'mac': mac,
            'first_seen': now,
            'last_seen': now,
            'arp_requests': 0,
            'arp_replies': 0,
            'spoofing_count': 0,
            'icmp_count': 0,
        }
    else:
        if devices[ip]['mac'] != mac:
            devices[ip]['spoofing_count'] += 1
            print(f"SPOOFING: {ip} changed MAC from {devices[ip]['mac']} to {mac}")
            devices[ip]['mac'] = mac
        
        devices[ip]['last_seen'] = now


# FUNCIONES DE DETECCIÓN
def check_ip_spoofing(src_ip, src_mac):
    '''IPV4 mac == ARP mac'''
    if src_ip in devices:
        if devices[src_ip]['mac'] != src_mac:
            pass  # Ya detectado en update_device()

def check_arp_flood(sender_ip):
    """ARP request flooding"""
    if sender_ip not in devices:
        return
    
    time_diff = time.time() - devices[sender_ip]['first_seen']
    
    if time_diff > 0:
        rpm = devices[sender_ip]['arp_requests'] / (time_diff / 60)
        
        if rpm > ARP_REQUEST_THRESHOLD:
            print(f"ARP_FLOOD: {sender_ip} sending {rpm:.1f} requests/min")

def check_icmp_flood(sender_ip):
    if sender_ip not in devices:
        return
    
    return


def clean_inactive_devices():
    current_time = time.time()
    inactive = []
    
    for ip, data in devices.items():
        if current_time - data['last_seen'] > TTL:
            inactive.append(ip)
    
    for ip in inactive:
        del devices[ip]


# FUNCIONES DE PARSEO
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


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


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def arp_packet(data):
    opCode, sender_MAC, sender_IP, target_MAC, target_IP = struct.unpack('! 6x H 6s 4s 6s 4s', data[:28])
    
    sender_MAC = get_mac_addr(sender_MAC)
    sender_IP = ipv4(sender_IP)
    target_MAC = get_mac_addr(target_MAC)
    target_IP = ipv4(target_IP)
    
    opCode = 'REQUEST' if opCode == 1 else 'REPLY' if opCode == 2 else 'UNKNOWN'
    
    return opCode, sender_MAC, sender_IP, target_MAC, target_IP


if __name__ == '__main__':
    main()