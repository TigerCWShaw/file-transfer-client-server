# %%
import socket, sys, os
import ipaddress
from time import sleep, perf_counter
import threading
import socketserver
import signal
import copy
import ast

buffer_size = 1024
exit_program = False
haveInput = False
file_list = {}

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
    exit_program = True
    sys.exit()

def isDir(path):
    if os.path.exists(path):
        return True
    return False

def isFile(file, path):
    if os.path.exists(os.path.join(path, file)):
        return True
    return False

def printTable():
    global file_list
    # print(file_list)
    print_list = []
    for name, value in file_list.items():
        for file in value['files']:
            print_list.append([file, name, value['ip'], value['tcp_port']])
    if len(print_list) > 0:
        print_list.sort()
        msg = 'FILENAME\tOWNER\tIP ADDRESS\tTCP PORT\n'
        for i, plist in enumerate(print_list):
            for v in plist:
                msg += str(v) + '\t'
            if i < len(print_list) - 1:
                msg += '\n'
        print(msg)
    else:
        print('>>> [No files available for download at the moment.]')

# %% Client side of the program


def client_tcp_conn(server_address, client_tcp_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
        tcp_sock.bind(('127.0.0.1', client_tcp_port))
        tcp_sock.connect(server_address)

        print('In tcp connection')
        # msg = tcp_sock.recv(buffer_size)
        # msg_str = msg.decode('utf-8')

def handle_udp_best_effort(udp_sock, msg_table):
    while not exit_program:
        remove_list = []
        # value:[msg, count, time]
        for address, value in msg_table.items():
            current_time = perf_counter()
            if current_time - value[2] >= 0.5:
                # print(current_time - value[2])
                if value[1] >= 3:
                    remove_list.append(address)
                    print('[No ACK from Server, please try again later.]\n>>> ')
                    continue
                udp_sock.sendto(value[0].encode(), address)
                # increase the total count and update time
                value[2] = current_time
                value[1] += 1
            else:
                # dict key is in insertion order
                break
        for address in remove_list:
            msg_table.pop(address)

def handle_udp_send(udp_sock, server_address, name, client_tcp_port, msg_table):
    global exit_program, haveInput
    set_dir = False
    file_path = ''
    # send registration data first
    reg = '#reg' + name + ' ' + str(client_tcp_port)
    udp_sock.sendto(reg.encode(), server_address)
    sleep(0.2)

    while not exit_program:
        sleep(0.2)
        try:
            # haveInput is used for output formatting
            haveInput = False
            cmd = input('>>> ')
            haveInput = True

            if not cmd:
                continue
            tmp_cmd =  cmd.split(' ')
            if cmd == 'list':
                printTable()
            elif tmp_cmd[0] == 'setdir' and len(tmp_cmd) == 2:
                if isDir(tmp_cmd[1]):
                    cmd = '#set' + name
                    set_dir = True
                    file_path = tmp_cmd[1]
                    udp_sock.sendto(cmd.encode(), server_address)
                    print('>>> [Successfully set ' + tmp_cmd[1] + ' as the directory for searching offered files.]')
                else:
                    print('>>> [setdir failed: ' + tmp_cmd[1] + ' does not exist.]')
            elif tmp_cmd[0] == 'offer' and len(tmp_cmd) >= 2:
                if not set_dir:
                    print('>>> [You need to setdir first.]')
                else:
                    file_valid = True
                    for i in range(1, len(tmp_cmd)):
                        if not isFile(tmp_cmd[i], file_path):
                            print('>>> ' + tmp_cmd[i] + ' does not exist')
                            file_valid = False
                            break
                    if file_valid:
                        cmd += ' ' + name
                        udp_sock.sendto(cmd.encode(), server_address)
                        msg_table[server_address] = [cmd, 1, perf_counter()]
            else:
                udp_sock.sendto(cmd.encode(), server_address)

        except KeyboardInterrupt:
            # close program when ctrl c
            exit_program = True
            udp_sock.close()
            break
        # except OSError:
        #     break


def handle_udp_recv(udp_sock, msg_table):
    global exit_program, haveInput, file_list
    haveInput = True
    while not exit_program:
        sleep(0.1)
        try:
            msg, server_address = udp_sock.recvfrom(buffer_size)
            udp_sock.sendto('ack'.encode(), server_address)
            msg_str = msg.decode('utf-8')
        except OSError:
            break
        if msg_str[:4] == '#ack':
            if server_address in msg_table:
                msg_table.pop(server_address)
            print('>>>', '[' + msg_str[4:] + ']')
        elif msg_str[:4] == '#log':
            # handle already logged in
            print('>>>', '[' + msg_str[4:] + ']')
            exit_program = True
            udp_sock.close()
        elif msg_str[:4] == '#tab':
            # handle updated table
            file_list = ast.literal_eval(msg_str[4:])
            if haveInput:
                print('>>> [Client table updated.]')
            else:
                print('[Client table updated.]\n>>> ', end='')
        else:
            print('>>>', '[' + msg_str + ']')

def client(name, server_ip , server_port, client_udp_port, client_tcp_port):
    msg_table = {}
    server_address = (server_ip, server_port)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', client_udp_port))

    udp_send_thread = threading.Thread(target=handle_udp_send, args=(udp_sock, server_address, name, client_tcp_port, msg_table))
    udp_recv_thread = threading.Thread(target=handle_udp_recv, args=(udp_sock, msg_table))
    udp_best_effort_thread = threading.Thread(target=handle_udp_best_effort, args=(udp_sock, msg_table))

    udp_best_effort_thread.start()
    udp_recv_thread.start()
    udp_send_thread.start()

    # udp_recv_thread.join()
    # udp_send_thread.join()



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

def sendTable(client_table, udp_sock):
    sub_table = getSubTable(client_table)
    msg = '#tab' + str(sub_table)
    # send new table to all online members
    for key, value in client_table.items():
        if value['status'] == True:
            udp_sock.sendto(msg.encode(), (value['ip'], value['udp_port']))

def handleRegistration(name, client_table, client_address, tcp_port):
    if name in client_table:
        if client_table[name]['status']:
            return '#logError: You are already logged in.'
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
        client_table[name]['set_dir'] = False
    return 'Welcome, You are registered.'

def handle_best_effort(udp_sock, msg_table):
    while True:
        remove_list = []
        # value:[msg, count, time]
        for client_address, value in msg_table.items():
            current_time = perf_counter()
            if current_time - value[2] >= 0.5:
                # print(current_time - value[2])
                udp_sock.sendto(value[0].encode(), client_address)
                # increase the total count and update time
                value[2] = current_time
                value[1] += 1
                if value[1] >= 3:
                    remove_list.append(client_address)
            else:
                # dict key is in insertion order
                break
        for client_address in remove_list:
            msg_table.pop(client_address)

def handle_client_request(udp_sock, client_table, msg_table):
    while True:
        msg=''
        msg, client_address = udp_sock.recvfrom(buffer_size)
        msg_str = msg.decode('utf-8')
        msg_list = msg_str.split(' ')

        if msg_str == 'ack':
            if client_address in msg_table:
                msg_table.pop(client_address)
        elif msg_str[0:4] == '#set':
            client_table[msg_str[4:]]['set_dir'] = True

        elif msg_str[0:4] == '#reg':
            # recieve name and tcp port from client
            k = msg_str[4:].split(' ')
            if len(k) == 2:
                msg = handleRegistration(k[0], client_table, client_address, int(k[1]))
                udp_sock.sendto(msg.encode(), client_address)
                if msg != '#logYou are already logged in.':
                    sub_table = getSubTable(client_table)
                    msg = '#tab' + str(sub_table)
                    udp_sock.sendto(msg.encode(), client_address)
                    # store message in buffer for best effort
                    msg_table[client_address] = [msg, 1, perf_counter()]
            else:
                msg = 'Invalid Request'

        elif msg_list[0] == 'offer' and len(msg_list) >= 3:
            # ignore first and last (command, name)
            name = msg_list[len(msg_list)-1]
            set_len = len(client_table[name]['files'])
            for i in range(1, len(msg_list)-1):
                client_table[name]['files'].add(msg_list[i])
            if len(client_table[name]['files']) > set_len:
                msg = '#ackOffer Message Received By Server'
                udp_sock.sendto(msg.encode(), client_address)
                # broadcast changes to files
                sendTable(client_table, udp_sock)
            else:
                msg = '#ackNo New Files Added'
                udp_sock.sendto(msg.encode(), client_address)

        else:
            msg = 'Invalid Request'
            udp_sock.sendto(msg.encode(), client_address)

        print('Message from client at', client_address, ':', msg_str)

def server(port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', port))
    print('Server is listening at port', port)
    # table to store name, status, files, ip address, port
    client_table = {}
    msg_table = {}

    best_effort_thread = threading.Thread(target=handle_best_effort, args=(udp_sock, msg_table))
    client_request_thread = threading.Thread(target=handle_client_request, args=(udp_sock, client_table, msg_table))

    best_effort_thread.start()
    client_request_thread.start()

    best_effort_thread.join()
    client_request_thread.join()

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
                # signal.signal(signal.SIGINT, signal_handler)
                client(name, server_ip, server_port, client_udp_port, client_tcp_port)
        else:
            print('Invalid parameters for client mode')
    else:
        print('Please enter a valid mode (-c/-s)')


if __name__ == "__main__":
    main()