# %%
import socket, sys, os
import ipaddress
from time import sleep, perf_counter
import threading
import socketserver
import signal
import copy
import ast
import pandas as pd

buffer_size = 1024
exit_program = False
haveInput = False
file_list = {}
file_path = ''
logout = False

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
        # msg = 'FILENAME\tOWNER\tIP ADDRESS\tTCP PORT\n'
        # for i, plist in enumerate(print_list):
        #     for v in plist:
        #         msg += str(v) + '\t'
        #     if i < len(print_list) - 1:
        #         msg += '\n'
        # print(msg)
        df = pd.DataFrame(print_list, columns=['FILENAME', 'OWNER', 'IP ADDRESS', 'TCP PORT'])
        with pd.option_context('display.max_rows', None,
                       'display.max_columns', None,
                       'display.precision', 3,
                       ):
            print(df)
    else:
        print('>>> [No files available for download at the moment.]')

# %% Client side of the program
def tcp_file_transfer(peer_name, peer_address, file_name, name):
    global file_path
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
        tcp_sock.connect(peer_address)
        print('< Connection with client ' + peer_name + ' established. >')
        # tell the peer which file
        msg = file_name + ' ' + name
        tcp_sock.sendall(msg.encode())


        with open(file_name, 'w') as f:
            print('< Downloading ' + file_name + '... >')
            while True:
                data = tcp_sock.recv(buffer_size).decode()
                if not data:
                    break
                f.write(data)
            print('< ' + file_name + ' downloaded successfully! >')
        print('< Connection with client ' + peer_name + ' closed. >')

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # recieve filename from client
        global file_path, logout
        msg = self.request.recv(buffer_size).decode()
        if logout:
            return
        file_name, peer_name = msg.split(' ')
        print('\n< Accepting connection request from ' + self.client_address[0] + ' >')
        print('< Transferring ' + file_name + '... >')
        with open(os.path.join(file_path, file_name), 'r') as f:
            data = f.read()
            self.request.sendall(data.encode())
            print('< ' + file_name + ' transferred successfully! >')
        print('< Connection with client ' + peer_name + ' closed. >\n>>> ', end='')

def handle_tcp_recv(client_tcp_port):
    with socketserver.TCPServer((socket.gethostbyname(socket.gethostname()), client_tcp_port), MyTCPHandler) as server:
        server.serve_forever()

def handle_udp_best_effort(udp_sock, msg_table, server_address):
    global logout
    while not exit_program:
        if logout:
            continue
        remove_list = []
        # value:[msg, count, time]
        for key, value in msg_table.items():
            current_time = perf_counter()
            if current_time - value[2] >= 0.5:
                # print(current_time - value[2])
                if value[1] >= 3:
                    remove_list.append(key)
                    if key == '#offer':
                        print('[No ACK from Server, please try again later.]\n>>> ')
                    elif key == '#dereg':
                        print('[Server not responding]\n>>> [Exiting]')
                        logout = True
                    continue
                udp_sock.sendto(value[0].encode(), server_address)
                # increase the total count and update time
                value[2] = current_time
                value[1] += 1
            else:
                # dict key is in insertion order
                break
        for address in remove_list:
            msg_table.pop(address)

def handle_udp_send(udp_sock, server_address, name, client_tcp_port, msg_table):
    global exit_program, haveInput, file_list, logout
    set_dir = False
    global file_path
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
            tmp_cmd =  cmd.split(' ')
            if tmp_cmd[0] == 'login' and len(tmp_cmd) == 2:
                # login
                if logout == False:
                    print('You Need to dereg first')
                else:
                    logout = False
                    reg = '#reg' + tmp_cmd[1] + ' ' + str(client_tcp_port)
                    udp_sock.sendto(reg.encode(), server_address)
            elif not cmd or logout:
                continue
            elif cmd == 'list':
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
                        msg_table['#offer'] = [cmd, 1, perf_counter()]
            elif tmp_cmd[0] == 'request' and len(tmp_cmd) == 3:
                # input: request <file> <name>
                # check if name exists
                if tmp_cmd[2] not in file_list or tmp_cmd[2] == name:
                    print('< Invalid Request >')
                    continue
                if tmp_cmd[1] not in file_list[tmp_cmd[2]]['files']:
                    print('< Invalid Request >')
                    continue
                # establish tcp connection with file owner
                peer_address = (file_list[tmp_cmd[2]]['ip'], file_list[tmp_cmd[2]]['tcp_port'])
                tcp_file_transfer(tmp_cmd[2], peer_address, tmp_cmd[1], name)
            elif tmp_cmd[0] == 'dereg' and len(tmp_cmd) == 2:
                if tmp_cmd[1] == name:
                    # close tcp port
                    udp_sock.sendto(cmd.encode(), server_address)
                    msg_table['#dereg'] = [cmd, 1, perf_counter()]
                else:
                    print('>>> [You cannot dereg other clients.]')
            else:
                udp_sock.sendto(cmd.encode(), server_address)

        except KeyboardInterrupt:
            # close program when ctrl c
            exit_program = True
            # udp_sock.close()
            break
        # except OSError:
        #     break


def handle_udp_recv(udp_sock, msg_table):
    global exit_program, haveInput, file_list, logout
    haveInput = True
    while not exit_program:
        sleep(0.1)
        if logout:
            continue
        try:
            msg, server_address = udp_sock.recvfrom(buffer_size)
            udp_sock.sendto('ack'.encode(), server_address)
            msg_str = msg.decode('utf-8')
        except OSError:
            break
        if msg_str[:4] == '#ack':
            if '#offer' in msg_table:
                msg_table.pop('#offer')
            print('>>>', '[' + msg_str[4:] + ']')
        elif msg_str[:5] == '#exit':
            if '#dereg' in msg_table:
                msg_table.pop('#dereg')
            print('>>>', '[' + msg_str[5:] + ']')
            logout = True
        elif msg_str[:4] == '#log':
            # handle already logged in
            print('>>>', '[' + msg_str[4:] + ']')
            exit_program = True
            # udp_sock.close()
        elif msg_str[:4] == '#tab':
            # handle updated table
            file_list = ast.literal_eval(msg_str[4:])
            if haveInput:
                print('>>> [Client table updated.]')
            else:
                print('[Client table updated.]\n>>> ', end='')
        elif msg_str[:5] == '#exit':
            print('>>>', '[' + msg_str[5:] + ']')
            logout = True
        else:
            print('>>>', '[' + msg_str + ']')

def client(name, server_ip , server_port, client_udp_port, client_tcp_port):
    msg_table = {}
    server_address = (server_ip, server_port)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((socket.gethostbyname(socket.gethostname()), client_udp_port))

    tcp_recv_thread = threading.Thread(target=handle_tcp_recv, args=(client_tcp_port,))
    tcp_recv_thread.start()

    udp_send_thread = threading.Thread(target=handle_udp_send, args=(udp_sock, server_address, name, client_tcp_port, msg_table))
    udp_recv_thread = threading.Thread(target=handle_udp_recv, args=(udp_sock, msg_table))
    udp_best_effort_thread = threading.Thread(target=handle_udp_best_effort, args=(udp_sock, msg_table, server_address))

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

def handle_register(name, client_table, client_address, tcp_port):
    if name in client_table:
        if client_table[name]['status']:
            return '#logError: You are already logged in.'
        else:
            client_table[name]['status'] = True
            return 'Welcome back ' + name + '.'
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
        print('Message from client at', client_address, ':', msg_str)

        if msg_str == 'ack':
            if client_address in msg_table:
                msg_table.pop(client_address)
        elif msg_str[0:4] == '#set':
            client_table[msg_str[4:]]['set_dir'] = True

        elif msg_str[0:4] == '#reg':
            # recieve name and tcp port from client
            k = msg_str[4:].split(' ')
            if len(k) == 2:
                msg = handle_register(k[0], client_table, client_address, int(k[1]))
                udp_sock.sendto(msg.encode(), client_address)
                if msg != '#logYou are already logged in.':
                    if len(client_table[k[0]]['files']) > 0:
                        sendTable(client_table, udp_sock)
                    else:
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
        elif msg_list[0] == 'dereg' and len(msg_list) == 2:
            client_table[msg_list[1]]['status'] = False
            if len(client_table[msg_list[1]]['files']) > 0:
                sendTable(client_table, udp_sock)
            msg = '#exitYou are Offline. Bye.'
            udp_sock.sendto(msg.encode(), client_address)
        else:
            msg = 'Invalid Request'
            udp_sock.sendto(msg.encode(), client_address)



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