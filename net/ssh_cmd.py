import sys
import paramiko


class SshClient:
    def __init__(self, ip: str, port: int | str, user: str, passwd:str):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if isinstance(port, str):
            port = int(port)
        
        self._client.connect(ip, port=port, username=user, password=passwd)
    
    def exec_command(self, cmd: str):
        _, stdout, stderr = self._client.exec_command(cmd)
    
        if (output := stdout.readlines() + stderr.readlines()):
            print('--- Output ---')
            for line in output:
                print(line)
                
    def close(self):
        self._client.close()
            
if __name__ == "__main__":
    import getpass
    
    if len(sys.argv) != 2:
        print("Wrong arguments.\nUsage: ./ssh_cmd.py 192.168.1.203:2222")
        sys.exit(1)
    
    user = input('Username: ')
    password = getpass.getpass()
    
    ip, port = sys.argv[1].split(':')
    client = SshClient(ip, port, user, password)
    
    while True:
        if (command := input("Command: ").strip()) == 'exit':
            print('[*] Exiting...')
            client.close()
            sys.exit(0)
            
        client.exec_command(command)
    
