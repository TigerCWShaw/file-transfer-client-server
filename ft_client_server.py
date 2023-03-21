# %%
import socket, sys
import ipaddress
from time import sleep
import threading
import socketserver
import signal
import copy
import ast

buffer_size = 1024
exit_program = False

# %% utility functions
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

def signal_handler(sig, frame):
    global exit_program
    print('[Exiting]')
    # sleep(0.2)
    sys.exit()

def printTable():
    pass

# %% Client side of the program
def client_tcp_conn(server_address, client_tcp_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
        tcp_sock.bind(('127.0.0.1', client_tcp_port))
        tcp_sock.connect(server_address)

        print('In tcp connection')
        # msg = tcp_sock.recv(buffer_size)
        # msg_str = msg.decode('utf-8')

def handle_udp_send(udp_sock, server_address, name, client_tcp_port):
    global exit_program
    # send registration data first
    reg = '#reg' + name + ' ' + str(client_tcp_port)
    udp_sock.sendto(reg.encode(), server_address)
    sleep(0.25)

    while not exit_program:
        sleep(0.25)
        try:
            cmd = input('>>> ')
            udp_sock.sendto(cmd.encode(), server_address)
        except EOFError:
            # close program when ctrl c
            exit_program = True
            udp_sock.close()
            break
        except OSError:
            break


def handle_udp_recv(udp_sock):
    current_filelist = {}
    global exit_program
    while not exit_program:
        sleep(0.1)
        try:
            msg, server_address = udp_sock.recvfrom(buffer_size)
            msg_str = msg.decode('utf-8')
        except OSError:
            break

        if msg_str[:4] == '#log':
            # handle already logged in
            print('test')
            print('>>>', '[' + msg_str[4:] + ']')
            exit_program = True
            udp_sock.close()
        elif msg_str[:4] == '#tab':
            # handle updated table
            current_filelist = ast.literal_eval(msg_str[4:])
            print('>>> [Client table updated.]')
        else:
            print('>>>', '[' + msg_str + ']')

def client(name, server_ip , server_port, client_udp_port, client_tcp_port):
    server_address = (server_ip, server_port)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', client_udp_port))

    udp_send_thread = threading.Thread(target=handle_udp_send, args=(udp_sock, server_address, name, client_tcp_port))
    udp_recv_thread = threading.Thread(target=handle_udp_recv, args=(udp_sock,))

    udp_recv_thread.start()
    udp_send_thread.start()

    udp_recv_thread.join()
    udp_send_thread.join()



# %% Server Side of the program
def getSubTable(client_table):
    # return table with files, name, ip, tcp_port
    sub_table = {}
    for key, value in client_table.items():
        if value['status'] == True:
            sub_table[key] = {}
            for i in ('ip', 'files', 'tcp_port'):
                sub_table[key][i] = copy.deepcopy(value[i])
    return sub_table

def handleRegistration(name, client_table, client_address, tcp_port):
    if name in client_table:
        if client_table[name]['status']:
            return '#logYou are already logged in.'
        else:
            client_table[name]['status'] = True
            return 'Welcome back ' + name
    else:
        client_table[name] = {}
        client_table[name]['ip'] = client_address[0]
        client_table[name]['udp_port'] = client_address[1]
        client_table[name]['tcp_port'] = tcp_port
        client_table[name]['files'] = set()
        client_table[name]['status'] = True
    return 'Welcome, You are registered.'



def server(port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', port))
    print('Server is listening at port', port)
    # table to store name, status, files, ip address, port
    client_table = {}

    while True:
        msg, client_address = udp_sock.recvfrom(buffer_size)
        msg_str = msg.decode('utf-8')

        if msg_str[0:4] == '#reg':
            # recieve name and tcp port from client
            k = msg_str[4:].split(' ')
            if len(k) == 2:
                msg = handleRegistration(k[0], client_table, client_address, int(k[1]))
                udp_sock.sendto(msg.encode(), client_address)

                # create a sub dict with files, name, ip, tcp_port
                sub_table = getSubTable(client_table)
                msg = '#tab' + str(sub_table)
                udp_sock.sendto(msg.encode(), client_address)
            else:
                msg = 'Invalid command'
        else:
            msg = 'Recieved command'
            udp_sock.sendto(msg.encode(), client_address)

        print('Message from client at', client_address, ':', msg_str)

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
                signal.signal(signal.SIGINT, signal_handler)
                client(name, server_ip, server_port, client_udp_port, client_tcp_port)
        else:
            print('Invalid parameters for client mode')
    else:
        print('Please enter a valid mode (-c/-s)')


if __name__ == "__main__":
    main()