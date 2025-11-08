#!/usr/bin/python3
# socks5 proxy with added frustration
# adatped from https://github.com/CodeWithImm/socks5_proxy/blob/main/socks5_proxy.py.py
# MIT License

import yaml
import socket
import select
from struct import pack, unpack
import traceback
from threading import Thread, activeCount, Lock, Semaphore
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
import time
import random
from queue import Queue
from collections import deque

BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '127.0.0.1'
LOCAL_PORT = 9067
OUTGOING_INTERFACE = ""

print(f"Trying to host on {LOCAL_ADDR}:{LOCAL_PORT}")

# consts

# proxy protocol consts
VER = b'\x05'
M_NOAUTH = b'\x00'
M_NOTAVAILABLE = b'\xff'
CMD_CONNECT = b'\x01'
ATYP_IPV4 = b'\x01'
ATYP_DOMAINNAME = b'\x03'

# interdiction config
with open('config.yaml', 'r') as f:
    data = yaml.load(f, Loader=yaml.SafeLoader)

aggressiveness = 1 # affects the aggressiveness of the decay function 
delay = 5 # in minutes
window = 60 # in minutes
sensitivity = 1 # number of packets required before it considers an app in use

blocklist = dict()
for link in data['blocklist']:
    blocklist[link.encode()] = [0, deque([0]*60), 0] # running total, count per minute, total in current minute
delay = data['delayTime']
aggressiveness = data['aggressivness']



# blocklist[b"www.reddit.com"] = 1
# blocklist[b"preview.redd.it"] = 1
# blocklist[b"www.instagram.com"] = 1
# blocklist[b"gateway.instagram.com"] = 1
starttime = time.time()
minute_boundary = starttime
sem = Semaphore()

exit = False


def error(msg="", err=None):
    print(msg)
    traceback.print_exc()


async def proxy_loop(socket_src, socket_dst, dst_addr): # listen for new data in either client or destination sockets, forward directly
    while not exit:
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        # on minute boundary, update all lists by popping last minute and subtracting total
        if time.time() - minute_boundary > 60:
            minute_boundary = time.time()
            async with sem.acquire():
                for b in blocklist:
                    window_remove = b[1].popleft()
                    b[1].append(b[2])
                    b[2] = 0
                    b[0] -= window_remove
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data: # TCP connection has been closed
                    return
                print(f"Processing Message to/from {dst_addr}")

                if any([substring in element for element in l]):
                    # add to the number of requests made (in minute and total)
                    async with sem.acquire():
                        b = blocklist[dst_addr]
                        b[2] += 1
                        b[0] += 1
                        # if more than limit, throttle
                        if b[0] > 20:
                            time.sleep(random.random() / 5)
                            print(f"Blocking Message to/from {dst_addr}")
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            exit = True
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def request_client(wrapper): # Parse destination address and port from client request
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or # establish a TCP/IP stream connection ONLY
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4: # parses destination information
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else: # DO NOT SUPPORT IPV6
        return False
    print(dst_addr, dst_port)
    return (dst_addr, dst_port)


def request(wrapper):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = request_client(wrapper)
    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
    if not dst or socket_dst == 0:
        rep = b'\x01' # tell the client that DST no worky or that it was invalid dst.
    else:
        rep = b'\x00' # send client details for the bound destination server
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00': # if handshake was successful, start proxy itself.
        proxy_loop(wrapper, socket_dst, dst[0])
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods: # means it's an invalid identification packet'
        return M_NOTAVAILABLE
    for method in methods: # checking if the method requested by the client is no auth. This proxy doesn't support authenticated SOCKS5 connections.'
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper) # checks if the identificaiton packet sent by client is valid and does not use authentication.
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    return True


def connection(wrapper):
    """ Function run by a thread """
    if subnegotiation(wrapper): # basically the SOCKS5 handshake
        request(wrapper)


def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock


def bind_port(sock):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    exit = true


def main():
    """ Main function """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not exit:
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()


if __name__ == '__main__':
    main()
