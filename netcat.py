import os
import argparse
import socket
import subprocess
import shlex
import textwrap
import sys
import threading


def execute(cmd: str):
    if not (cmd := cmd.strip()):
        return ""
    
    kwargs = {"stderr": subprocess.STDOUT}
    
    if os.name == 'nt':
        kwargs['shell'] = True
    
    try:
        output = subprocess.check_output(shlex.split(cmd), **kwargs)
    except Exception as e:
        return f'Error occured: {e}\n'
    
    if os.name == 'nt':
        return output.decode('cp1252')
    else:
        return output.decode()


class NetCat:
    def __init__(self, args, buffer) -> None:
        self._args = args
        self._buffer = buffer
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def run(self):
        if self._args.listen:
            self.listen()
        else:
            self.send()
            
    def send(self):
        self._socket.connect((self._args.target, self._args.port))
        input_str = f"Target ({self._args.target}:{self._args.port}) >"
        if self._buffer:
            self._socket.send(self._buffer)
        
        try:
            while True:
                recv_len = 1
                response = ""
                while recv_len:
                    data = self._socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                
                if response:
                    print(response)
                    buffer = input(input_str)
                    buffer += "\n"
                    self._socket.send(buffer.encode())
        
        except KeyboardInterrupt:
            print("User terminated...")
            self._socket.close()
            sys.exit()
    
    def listen(self):
        self._socket.bind((self._args.target, self._args.port))
        self._socket.listen(5)
        print(f"[*] Listen on {self._args.target}:{self._args.port}")
        
        while True:
            client_sock, _ = self._socket.accept()
            handler = threading.Thread(target=self.handle, args=(client_sock,))
            handler.start()
        
    def handle(self, client_sock):
        print('Handling...')
        if self._args.execute:
            output = execute(self._args.execute)
            client_sock.send(output.encode())
        
        elif self._args.upload:
            file_buffer = b''
            
            while True:
                data = client_sock.recv(4096)
                
                if not data:
                    break
                
                file_buffer += data
            
            with open(self._args.upload, 'wb') as f:
                f.write(file_buffer)
                
            client_sock.send(f'Saved file {self._args.upload}'.encode())
        
        elif self._args.command:
            cmd_buffer = b''
            client_sock.send(b'BHP: #> ')
            
            while True:
                try:
                    while b'\n' not in cmd_buffer:
                        cmd_buffer += client_sock.recv(64)
                        
                    if (cmd := cmd_buffer.decode()) == "\n":
                        client_sock.send(b'BHP: #> ')
                        
                    if (response := execute(cmd)):
                        client_sock.send(response.encode())
                    
                    cmd_buffer = b''
                    
                except Exception as e:
                    print(f'Server was killed by: {e}')
                    self._socket.close()
                    sys.exit()

        print(f"Connection was closed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BHP Net Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            netcat.py -t 192.168.0.102 -p 9000 -l -c # Cmd shell
            netcat.py -t 192.168.0.102 -p 9000 -l -u=./file.txt
        '''))
    
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()
    
    if args.listen:
        buffer = ''
    else:
        buffer = input()
        
    nc = NetCat(args, buffer.encode())
    nc.run()
    
