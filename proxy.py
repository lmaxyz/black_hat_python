from email.header import Header
from dataclasses import dataclass
import sys
import socket
import threading

HEX_FILTER = ''.join([(len(repr((u_ch := chr(i)))) == 3) and u_ch or '.' for i in range(256)])


@dataclass
class Target:
    host: str
    port: int
    
    def as_tuple(self):
        return (self.host, self.port)


def hex_dump(src: str|bytes, length=16, show=True) -> (list[str] | None):
    if isinstance(src, bytes):
        src = src.decode()
        
    result = list()
    
    for i in range(0, len(src), length):
        word = str(src[i:i+length])
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join((f'{ord(c):02X}' for c in word))
        hexwidth = length*3
        
        result.append(f'{i:04X}\t{hexa:<{hexwidth}}\t{printable}')
        
    if show:
        for line in result:
            print(line)
    else:
        return result


def receive_from(connection: socket.socket) -> bytes:
    buff = b''
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buff += data
            
    except Exception as e:
        pass
    
    return buff


def request_handler(traffic: bytes):
    return traffic


def response_handler(traffic: bytes):
    return traffic


def proxy_handler(client_socket: socket.socket, remote: Target, recieve_first: bool):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect(remote.as_tuple())
    
    if recieve_first:
        remote_buffer = receive_from(remote_socket)
        hex_dump(remote_buffer)
        remote_buffer = response_handler(remote_buffer)
        if (buff_len := len(remote_buffer)):
            print(f"[<==] Sending {buff_len} bytes to localhost.")
            client_socket.send(remote_buffer)
    
    while True:
        local_buff = receive_from(client_socket)
        if (local_buff_len := len(local_buff)):
            print(f"[==>]Received {local_buff_len} bytes from localhost.")
            hex_dump(local_buff)
            local_buff = request_handler(local_buff)
            remote_socket.send(local_buff)
            print("[==>] Sent to remote.")
        
        remote_buffer = receive_from(remote_socket)
        if (remote_buff_len := len(remote_buffer)):
            print(f"[==>]Received {remote_buff_len} bytes from remote.")
            hex_dump(remote_buffer)
            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[==>] Sent to localhost.")
            
        if not remote_buff_len or not local_buff_len:
            try:
                print("[*] No more data. Closing connections.")
                client_socket.close()
                remote_socket.close()
            except Exception as e:
                print(f"Something went wrong {e}")
            finally:
                break


def server_loop(local: Target, remote: Target, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server.bind(local.as_tuple())
    except Exception as e:
        print('problem on bind: %r' % e)
        print(f"[!!] Failed to listen on {local.host}:{local.port}")
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)
        
    print(f"[*] Listening on {local.host}:{local.port}")
    
    server.listen(5)
    server.settimeout(5)
    while True:
        try:
            client_socket, addr = server.accept()
        except TimeoutError:
            continue

        print(f"> Received incoming connection from {addr[0]}:{addr[1]}")
        proxy_worker = threading.Thread(target=proxy_handler,
                                        args=(client_socket, remote, receive_first))
        proxy_worker.start()


def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)
    
    local = Target(sys.argv[1], int(sys.argv[2]))
    remote = Target(sys.argv[3], int(sys.argv[4]))
    
    if 'true' in sys.argv[5].lower():
        receive_first = True
    else:
        receive_first = False
    
    try:
        server_loop(local, remote, receive_first)
    except KeyboardInterrupt:
        print("Interrupted by user.\nExiting...")


if __name__ == "__main__":
    main()
    
