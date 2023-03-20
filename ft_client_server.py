# %%
import socket, sys
import ipaddress
from time import sleep
import threading

buffer_size = 1024

# %% utitility functions
def isIp(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print('Invalid IP address')
        return False

def isPort(port):
    if port < 1024  or port > 65535:
        print('Invalid port number')
        return False
    return True

# %% Client side of the program
def client_tcp_conn():
    pass

def client_udp_conn(server_address, client_udp_port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', client_udp_port))

    while True:
        cmd = input('>>> ')
        if not cmd:
            continue
        # sock.sendall(cmd.encode())
        udp_sock.sendto(cmd.encode(), server_address)
        sleep(0.5)
        # msg = sock.recv(1024)
        msg, server_address = udp_sock.recvfrom(buffer_size)
        if not msg:
            break
        msg_str = '[' + msg.decode('utf-8') + ']'
        print('>>>', msg_str)

def client(server_ip , server_port, client_udp_port, client_tcp_port):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind(('127.0.0.1', client_tcp_port))

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', client_udp_port))
    server_address = (server_ip, server_port)
    # sock.connect((server_ip, server_port))
    # msg = sock.recv(1024)
    # msg_str = msg.decode('utf-8')

    while True:
        cmd = input('>>> ')
        if not cmd:
            continue
        # sock.sendall(cmd.encode())
        udp_sock.sendto(cmd.encode(), server_address)
        sleep(0.5)
        # msg = sock.recv(1024)
        msg, server_address = udp_sock.recvfrom(buffer_size)
        if not msg:
            break
        msg_str = '[' + msg.decode('utf-8') + ']'
        print('>>>', msg_str)


# %% Server Side of the program
def server(port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', port))
    print('Server is listening at port ', port)
    client_table = {}

    while(True):
        msg, client_address = udp_sock.recvfrom(buffer_size)
        msg_str = msg.decode('utf-8')

        print('Message from client at', client_address, ':', msg_str)

        # send reply to client
        msg = 'Welcome, You are registered.'
        udp_sock.sendto(msg.encode(), client_address)

# %% main
def main():
    mode = sys.argv[1]
    if mode == '-s':
        if len(sys.argv) == 3:
            server_port = int(sys.argv[2])
            if isPort(server_port):
                server(server_port)
        else:
            print('Invalid parameters for server mode')
    elif mode == '-c':
        if len(sys.argv) == 7:
            name = sys.argv[2]
            server_ip = sys.argv[3]
            server_port = int(sys.argv[4])
            client_udp_port = int(sys.argv[5])
            client_tcp_port = int(sys.argv[6])

            if isIp(server_ip) and isPort(server_port) and isPort(client_udp_port) and isPort(client_tcp_port):
                client(server_ip, server_port, client_udp_port, client_tcp_port)
        else:
            print('Invalid parameters for client mode')
    else:
        print('Please enter a valid mode (-c/-s)')


if __name__ == "__main__":
    main()