from pickle import FALSE, TRUE
import sys
import threading
from threading import Thread
import socket
import binascii
import selectors
import time
import types
log = []
sel = selectors.DefaultSelector()

class connection():
    def __init__(self):
        self.connected = 0
        self.client_ip = None
        self.client_port = None
        self.got_syn = 0
        self.got_ack = 0
        self.message = None
        self.data_port = None
        self.closed = 0

class TCP_header():
    def __init__(self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port):
        self.source_prt = src_port  # 16 bits
        self.destination_prt = dst_port # 16 bits
        self.sequence_num = seq_num  # 32 bits
        self.ACK_num = ack_num # 32 bits
        # self.header_length = 0 # 4 bits
        # self.unused = 0 # 4 bits
        # self.CWR = 0 # 1 bit
        # self.ECE = 0 # 1 bit
        # self.URG = 0 # 1 bit
        self.ACK = ack  # ack flag 0 if not ack, 1 if syn-ack or ack
        # self.PSH = 0 # 1 bit
        # self.RST = 0 # 1 bit
        self.SYN = syn  # syn flag 0 if not syn, 1 if syn-ack or syn
        self.FIN = fin # 1 bit
        # self.receive_window = 0 # 16 bits
        # self.internet_checksum = 0 # 16 bits
        # self.urgent_data_ptr = 0 # 16 bits
        # self.options = 0
        self.data = data
    def get_bits(self):
        bits = '{0:016b}'.format(self.source_prt)
        bits += '{0:016b}'.format(self.destination_prt)
        bits += '{0:032b}'.format(self.sequence_num)
        bits += '{0:032b}'.format(self.ACK_num)
        bits += '{0:01b}'.format(self.SYN)
        bits += '{0:01b}'.format(self.ACK)
        bits += '{0:01b}'.format(self.FIN)
        if self.data != "":
            bits += self.data
        return bits.encode()
    def custom_message(self, ack, syn, fin):

        self.ACK = ack #ack flag 0 if not ack, 1 if syn-ack or ack

        self.SYN = syn #syn flag 0 if not syn, 1 if syn-ack or syn
        self.FIN = fin
    def get_type(self):
        if self.ACK == 1 and self.SYN == 1:
            return "SYN-ACK"
        elif self.ACK == 1:
            return "ACK"
        elif self.SYN == 1:
            return "SYN"
        elif self.FIN == 1:
            return "FIN"
        elif self.data != "":
            return "DATA"
def send_packet(message, DNS_IP, DNS_PORT, socket_obj):
    address = (DNS_IP, DNS_PORT)

    our_socket = socket_obj  # Internet, UDP.
    # send message to given address

    print(message)

    our_socket.sendto(message, address)
def accept(welcome_socket, port): #basically accept
    try:
        packet, address = welcome_socket.recvfrom(1024)  # check this size
        connect = connection()
        print("handshake get SYN: ", packet)
        message = bits_to_header(packet)
        gotsyn = 0
        cur_seq = 0
        cur_ack = message.sequence_num
        print("received seq: ", message.sequence_num, " ack: ", message.ACK_num)
        if message.get_type() == "FIN":
            welcoming_closeconnection(welcome_socket,0, cur_seq, cur_ack,address[0], address[1], welcome_socket.getsockname()[1])
            return 0

        if message.get_type() == "SYN":
            print("got syn")
            print(address)
            connect.data_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            connect.data_port.bind(("127.0.0.1", 0))

            print(connect.data_port.getsockname()[1])
            synack = TCP_header(connect.data_port.getsockname()[1], 0, cur_ack+1, 0, 0, 0, "", port)
            synack.custom_message(1, 1, 0)

            got_syn = 1
            log.append([address[0], address[1], "SYNACK", len(synack.get_bits())])
            send_packet(synack.get_bits(), address[0], address[1], welcome_socket)

        packet2, address2 = welcome_socket.recvfrom(1024)
        message2 = bits_to_header(packet2)
        print("received seq: ", message2.sequence_num, " ack: ", message2.ACK_num)
        cur_seq = message2.ACK_num
        cur_ack = message2.sequence_num
        if message2.get_type() == "FIN":
            print("interruption")
            welcoming_closeconnection(welcome_socket,0, cur_seq, cur_ack, address[0], address[1], welcome_socket.getsockname()[1])
            return 0

        if message2.get_type() == "ACK" and got_syn == 1:
            print("check ack")
            connect.data_port.setblocking(False)
            curconnection = connect

            return curconnection.data_port, address
        else:
            print("Couldn't establish handshake...")
            return 0

    except KeyboardInterrupt:
        print("Keyboard Interruption")
        welcoming_closeconnection(welcome_socket,1, cur_seq, cur_ack, address[0], address[1], welcome_socket.getsockname()[1]) ##############
        return 0
def service_connection(key, mask):
    # Get the socket from the key
    try:
        sock = key.fileobj
        data = key.data
        address = 0
        if mask & selectors.EVENT_READ:
            # print the event
            print(f"Read event for {data.addr}")
            # If we can read, it means the socket is ready to receive data

            packet, address = sock.recvfrom(1024)  # check this size

            if packet:
                # If we have received data, store it in the data object
                message = bits_to_header(packet)
                print("received seq: ", message.sequence_num, " ack: ", message.ACK_num)
                cur_seq = message.ACK_num
                cur_ack = message.sequence_num + len(message.data) * 8
                print("sending seq: ", cur_seq, " ack: ", cur_ack)
                if message.get_type() == "FIN":
                    data_closeconnection(sock, 0, cur_seq, cur_ack+1, address[0], address[1], sock.getsockname()[
                        1])
                print(packet)
                if message.data == "Ping":
                    print("correct ping")
                else:
                    print("wrong data")
                    print(message.data)

                response = TCP_header(address[1], cur_seq, cur_ack, 0, 0, 0, "Pong", sock.getsockname()[1])
                packet = response.get_bits()

                log.append([address[0], address[1], "DATA", len(packet)])

                data.outb += packet
            else:
                # If we have received no data, it means the connection is closed
                print(f"Closing connection to {data.addr}")
                sel.unregister(sock)
                sock.close()
        if mask & selectors.EVENT_WRITE:
            # If we can write, it means the socket is ready to send data
            if data.outb:
                # If we have data to send, send it
                if address:
                    #print(f"Echoing {data.outb!r} to {data.addr}")
                    sent = sock.sendto(data.outb, (address[0], address[1]))
                    data.outb = data.outb[sent:]
    except KeyboardInterrupt:
        print("Keyboard Interruption")
        data_closeconnection(sock, 1,cur_seq, cur_ack, address[0], address[1],sock.getsockname()[1])  ##############
        return 0
def bits_to_header(bits):
    bits = bits.decode()
    src_port = int(bits[:16], 2)
    dst_port = int(bits[16:32], 2)
    seq_num = int(bits[32:64], 2)
    ack_num = int(bits[64:96], 2)
    syn = int(bits[96], 2)
    print(syn)
    ack = int(bits[97], 2)
    fin = int(bits[98], 2)
    print("in bits to header 1")
    try:
        data_string = bits[99:]
        print("in bits to header", data_string)
    except:
        data_string = ""
    return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, data_string, src_port)


def welcoming_closeconnection(welcome_socket, putah, cur_seq, cur_ack, address, dst_port, src_port):
    if putah == 1:
        ack = False
        while ack != True:
            message = TCP_header(dst_port,cur_seq,cur_ack,0,0,0, "", src_port)
            message.FIN = 1

            log.append([address, dst_port, "FIN", len(message.get_bits())])
            welcome_socket.sendto(message.get_bits(), (address, dst_port))

            data, addr = welcome_socket.recvfrom(1024)
            message = bits_to_header(data)

            if message.ACK == 1:
                break
    elif putah == 0:
        message = TCP_header(dst_port,cur_seq,cur_ack+1,0,0,0, "", src_port)
        message.ACK = 1

        log.append([address, dst_port, "ACK", len(message.get_bits())])
        welcome_socket.sendto(message.get_bits(), (address, dst_port))

    print("closing connection for port ")
    welcome_socket.close()
    welcome_close = 1

def data_closeconnection(curconnection,putah, cur_seq, cur_ack, address, dst_port, src_port):

    # putah = 0 -> client initiated close
    # putah = 1 -> server initiated close
    # putah = 2 -> wrong data
    if putah == 1:
        ack = False
        count = 0
        while ack != True or count != 3:
            message = TCP_header(dst_port,cur_seq,cur_ack,0,0,0, "", src_port)
            message.FIN = 1

            print("in data fin")
            log.append([address, dst_port, "FIN", len(message.get_bits())])
            curconnection.data_port.sendto(message.get_bits(), (address, dst_port))

            data, addr = curconnection.data_port.recvfrom(1024)
            message = bits_to_header(data)
            print("ack in fin", message.ACK)

            if message.ACK == 1:
                break
            count += 1
    elif putah == 0:
        message = TCP_header(dst_port,cur_seq,cur_ack,0,0,0, "", src_port)
        message.ACK = 1

        log.append([address, dst_port, "ACK", len(message.get_bits())])
        curconnection.sendto(message.get_bits(), (address, dst_port))

    print("closing connection for port ")
    curconnection.close()
    return 1

def accept_wrapper(sock, port):
    # Accept a connection and register the socket with the selector
    conn, addr = accept(sock, port)
    print(f"Accepted connection from {addr}")
    # Set the socket to non-blocking
    conn.setblocking(False)
    # Create a data object to store the connection id and the messages
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    # Register the socket with the selector
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

if __name__ == '__main__':
    threads = []
    client_ip = sys.argv[2]
    port = int(sys.argv[4])
    lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    lsock.bind((client_ip, port))

    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:

            events = sel.select(timeout=None)
            for key, mask in events:

                if key.data is None:

                    accept_wrapper(key.fileobj, port)
                else:

                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("keyboard interrupt")
    finally:
        sel.close()



#python3 server_putah.py --ip 127.0.0.1 --port 32007
#python3 client_putah.py --server_ip 127.0.0.1 --server_port 32007