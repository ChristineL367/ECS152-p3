
import sys
import socket
import binascii
import threading

log = []

def create_message():
    source_prt = 0
    destination_prt = 0
    sequence_num = 0
    ACK_num = 0
    header_length = 0
    unused = 0
    CWR = 0
    ECE = 0
    URG = 0
    ACK = 0
    PSH = 0
    RST = 0
    SYN = 0
    FIN = 0
    receive_window = 0
    internet_checksum = 0
    urgent_data_ptr = 0
    options = 0
    data = 0
def send_data_transfer(message):
    DNS_IP = "169.237.229.88"  # change this by country - currently for the USA
    DNS_PORT = 53

    READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.
    # send message to given address

    client.sendto(binascii.unhexlify(message), address)

    # receive message


    client.close()
def send_welcome_port(message): #message can be SYN, SYNACK, ACK, or FIN
    DNS_IP = "169.237.229.88"  # change this by country - currently for the USA
    DNS_PORT = 55 #diff port

    READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.
    # send message to given address

    client.sendto(message, address)

    # receive message

    client.close()

def logger(source, dest, type, length):
    log.append([source,dest,type,length])
def print_log():
    for i in log:
        print(i[0], "|", i[1], "|", i[2], "|", i[3])
if __name__ == '__main__':

    client_ip = sys.argv[2]
    port = sys.argv[4]