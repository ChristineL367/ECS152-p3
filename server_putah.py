from pickle import FALSE, TRUE
from client_putah import TCP_header
import sys
import threading
import socket
import binascii
log = []
class connection():
    def __init__(self):
        self.connected = 0
        self.client_ip = None
        self.client_port = None
        self.got_syn = 0
        self.got_ack = 0


class TCP_header():
    def __init__(self):
        self.source_prt = 0
        self.destination_prt = 0
        self.sequence_num = 0
        self.ACK_num = 0
        self.header_length = 0
        self.unused = 0
        self.CWR = 0
        self.ECE = 0
        self.URG = 0
        self.ACK = 0  # ack flag 0 if not ack, 1 if syn-ack or ack
        self.PSH = 0
        self.RST = 0
        self.SYN = 0  # syn flag 0 if not syn, 1 if syn-ack or syn
        self.FIN = 0
        self.receive_window = 0
        self.internet_checksum = 0
        self.urgent_data_ptr = 0
        self.options = 0
        self.data = ""
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
        elif self.data == "":
            return "DATA"
class TCP_over_UDP_server():
    def __init__(self, server_ip):
        self.connections = [] #queue
        self.welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.welcome_socket.bind(("127.0.01", 53))
        self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_socket.bind(("127.0.01", 1985))

        #self.lock = threading.Lock()

    def send_packet(self,message, DNS_IP, DNS_PORT, socket_obj):
        READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

        address = (DNS_IP, DNS_PORT)

        our_socket = socket_obj  # Internet, UDP.
        # send message to given address

        our_socket.sendto(message, address)
        #logger(53, DNS_PORT, type, length)
        # receive message

        #our_socket.close()
    def handshake(self, connection): #basically accept
        packet, address = self.welcome_socket.recvfrom(32) #check this size
        if packet.get_type() == "SYN":

            synack = TCP_header()
            synack.custom_message(1,1,0)
            connection.got_syn = 1
            self.send_packet(synack, client_ip, 8888, self.welcome_socket)

        packet2, address = self.welcome_socket.recvfrom(32)
        if packet2.get_type() == "ACK" and connection.got_syn == 1:
            connection.got_ack = 1
            connection.connected =1
            self.connections.append(connection)
            return 1
        else:
            print("Couldn't establish handshake...")
            return 0
    def data(self):
        #separate from welcome thread
        packet, address = self.welcome_socket.recvfrom(32)  # check this size
        if packet.get_type() == "FIN":
            return # figure out how to end the connection here
        while (1):
            if packet.get_type() == "FIN":
                break
            else:
                self.data_socket.listen()


    def thread_handshake(self):
        t = threading.Thread(target=self.handshake())
        t.daemon = True
        t.start()
    def logger(source, dest, type, length):
        log.append([source, dest, type, length])

if __name__ == '__main__':
    client_ip = sys.argv[2]
    port = sys.argv[4]