import os
import sys
import time
import socket
import struct
import ipaddress
import threading

from enum import IntEnum
from ctypes import Structure, c_ubyte, c_uint32, c_ushort


SUBNET = "192.168.0.0/24"
MAGIC_MSG = 'PYTHONRULES!'


class Protocol(IntEnum):
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17
        

class ICMP(Structure):
    _fields_ = [
        ("type",    c_ubyte,    8),
        ("code",    c_ubyte,    8),
        ("sum",     c_ushort,  16),
        ("id",      c_ushort,  16),
        ("seq",     c_ushort,  16),
    ]
    
    def __new__(cls, buff):
        return cls.from_buffer_copy(buff)
    
    def __init__(self, buffer=None):
        pass
    


class IP(Structure):
    _fields_ = [
        ("ihl",                 c_ubyte,        4),
        ("version",             c_ubyte,        4),
        ("tos",                 c_ubyte,        8),
        ("len",                 c_ushort,      16),
        ("id",                  c_ushort,      16),
        ("offset",              c_ushort,      16),
        ("ttl",                 c_ubyte,        8),
        ("protocol_num",        c_ubyte,        8),
        ("sum",                 c_ushort,      16),
        ("src",                 c_uint32,      32),
        ("dst",                 c_uint32,      32),
    ]
    
    def __new__(cls, buff):
        return cls.from_buffer_copy(buff)
    
    def __init__(self, buff=None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        
        try:
            self.protocol = Protocol(self.protocol_num).name
        except ValueError:
            self.protocol = str(self.protocol_num)


class UDPSender:
    def __init__(self, message: str|bytes|None = None):
        if isinstance(message, str):
            self._message = bytes(message, 'utf8')
        elif isinstance(message, bytes):
            self._message = message
        else:
            self._message = bytes(MAGIC_MSG, 'utf8')
        
    def __enter__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print('Sender socket opened.')
        return self
        
    def __exit__(self, exc_type, exc_value, exc_traceback):
        print('Sender socket closed.')
        self._socket.close()
        
    def send_messages_to_subnet(self, subnet:str):
        time.sleep(3)   # Time for sniffer starting.
        print('Start message sending...')
        for ip in ipaddress.ip_network(subnet).hosts():
            # print(f'Send message to {ip}')
            self._socket.sendto(self._message, (str(ip), 333))


class Sniffer:
    def __init__(self, host: str) -> None:
        self._host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
            
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self._sock.bind((host, 0))
        
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def sniff(self):
        hosts_up = set((f"{self._host} *",))
        
        try:
            if os.name == 'nt':
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            subnet = ipaddress.IPv4Network(SUBNET)
            message_as_bytes = bytes(MAGIC_MSG, 'utf8')
            message_len = len(MAGIC_MSG)
            print('Sniffing was started.')
            while True:
                buff = self._sock.recvfrom(65535)[0]
                # if message_as_bytes in buff:
                #     print(buff)
                ip_header = IP(buff[:20])
                
                if ip_header.protocol == 'ICMP':
                    # print(f"[{ip_header.protocol}] {ip_header.src_address} -> {ip_header.dst_address}")
                    # print(f"Version: {ip_header.version}")
                    # print(f"Header Length: {ip_header.ihl}")
                    
                    offset = ip_header.ihl * 4
                    icmp_buff = buff[offset:offset + 8]
                    icmp_header = ICMP(icmp_buff)
                    # print(f'ICMP -> Type: {icmp_header.type} Code: {icmp_header.code}\n')
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in subnet:
                            if buff[len(buff)-message_len:] == message_as_bytes:
                                if ip_header.src_address != self._host and ip_header.src_address not in hosts_up:
                                    hosts_up.add(ip_header.src_address)
                                    print(f'Host is up: {ip_header.src_address}')                 
        
        except KeyboardInterrupt:
            print('\nUser interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit(0)

        finally:
            if os.name == 'nt':
                print("Turn off rcvall...")
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.0.5'

    sniffer = Sniffer(host)
    sender = UDPSender()
    
    with sender as s:
        t = threading.Thread(target=s.send_messages_to_subnet, args=(SUBNET,))
        t.start()
        sniffer.sniff()
