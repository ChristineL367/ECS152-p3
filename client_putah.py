
import sys
import socket
import binascii
import threading

log = []
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

def send_synack(message, DNS_IP, DNS_PORT, type, length, client_socket):
    READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = client_socket  # Internet, UDP.
    # send message to given address

    client.sendto(message, address)
    logger(53, DNS_PORT, type, length)
    # receive message


    client.close()
def send_data_port(message): #message can be SYN, SYNACK, ACK, or FIN
    DNS_IP = "169.237.229.88"  # change this by country - currently for the USA
    DNS_PORT = 55 #diff port

    READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.
    # send message to given address

    client.sendto(message, address)

    # receive message

    client.close()
def connect():
    pass
def logger(source, dest, type, length):
    log.append([source,dest,type,length])
def print_log():
    for i in log:
        print(i[0], "|", i[1], "|", i[2], "|", i[3])
if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    server_ip = sys.argv[2]
    server_port = sys.argv[4]
    DNS_IP = "127.0.0.1"
    DNS_PORT = 8888 #let os choose port
    send_synack("ping", DNS_IP, DNS_PORT, "SYN", 0, client_socket)
    while True:
        if client_socket.recvfrom(server_port):
            print(client_socket.recvfrom(server_port))
            send_data_transfer("ping", DNS_IP, DNS_PORT, "ACK", 0, client_socket)
            break
    print_log()


