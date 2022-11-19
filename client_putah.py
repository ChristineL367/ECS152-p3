
import sys
import socket
import binascii
import threading
import time

log = {}
class TCP_header():

    def __init__(self, seq_num, ack_num, syn, ack, fin):
        self.source_prt = 0 # 16 bits
        self.destination_prt = 0 # 16 bits
        self.sequence_num = seq_num # 32 bits
        self.ACK_num = ack_num # 32 bits
        # self.header_length = 0 # 4 bits
        # self.unused = 0 # 4 bits
        # self.CWR = 0 # 1 bit
        # self.ECE = 0 # 1 bit
        # self.URG = 0 # 1 bit
        self.ACK = ack # ack flag 0 if not ack, 1 if syn-ack or ack
        # self.PSH = 0 # 1 bit
        # self.RST = 0 # 1 bit
        self.SYN = syn # syn flag 0 if not syn, 1 if syn-ack or syn
        self.FIN = fin # 1 bit
        # self.receive_window = 0 # 16 bits
        # self.internet_checksum = 0 # 16 bits
        # self.urgent_data_ptr = 0 # 16 bits
        # self.options = 0
        self.data = ""
    
    def header_only(self):
        pass

    
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
    
    # change this
    def get_bits(self):
        bits = '{0:016b}'.format(self.source_prt)
        bits += '{0:016b}'.format(self.destination_prt)
        bits = '{0:032b}'.format(self.seq_num)
        bits += '{0:032b}'.format(self.ack_num)
        bits += '{0:01b}'.format(self.syn)
        bits += '{0:01b}'.format(self.ack)
        bits += '{0:030b}'.format(0)
        return bits.encode()


class Client():
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.connection = False
    
    def handshake(self, address, port):
        
        global log
        # first handshake
        message = TCP_header(0,0,0,0,0)
        message.SYN = 1

        self.socket.sendto(message.get_bits(), (address, port))

        # receive second handshake
        data, addr = self.socket.recvfrom(1024)

        message = bits_to_header(data)
        
        if(message.SYN == 1 and message.ACK == 1):
            # send third handshake

            self.connection = True
            
            log[address].append(port) # get correct port for connecting socket
            print("Client Connection Established - IP: " + str(address) + " Port: " + str(port))
            message.SYN = 0

            self.socket.sendto(message.get_bits(), (address, port))
        
        if self.connection == True:
            self.udpconnect(address, port)
            
    def udpconnect(self, address, port):

        try:
            while self.connection:
                self.socket.sendto(b"Ping", (address,port)) 
                data, addr = self.socket.recvfrom(1024)

                time.sleep(4)
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(address,port)
    
    def closeconnection(self, address, port):
        ack = False

        while ack != True:
            message = TCP_header(0,0,0,0,1)
            self.socket.sendto(message.get_bits(), (address,port)) 

            data, addr = self.socket.recvfrom(1024)
            message = bits_to_header(data)

            if message.FIN == 1:
                break
        
        self.socket.close()


if __name__ == '__main__':
    pass

        















    




# def send_data_port(message, DNS_IP, DNS_PORT, type, length, client_socket): #message can be SYN, SYNACK, ACK, or FIN
#     DNS_IP = "169.237.229.88"  # change this by country - currently for the USA
#     DNS_PORT = 55 #diff port

#     READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

#     address = (DNS_IP, DNS_PORT)

#     client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.
#     # send message to given address

#     client.sendto(message, address)

#     logger(53, DNS_PORT, type, length)
#     # receive message

#     client.close()

# def connect():
    

# def logger(source, dest, type, length):
#     log.append([source,dest,type,length])

# def print_log():
#     for i in log:
#         print(i[0], "|", i[1], "|", i[2], "|", i[3])


# if __name__ == '__main__':
#     client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
#     server_ip = sys.argv[2]
#     server_port = sys.argv[4]
#     DNS_IP = "127.0.0.1"
#     DNS_PORT = 8888 #let os choose port
#     send_synack("ping", DNS_IP, DNS_PORT, "SYN", 0, client_socket)
#     while True:
#         if client_socket.recvfrom(server_port):
#             print(client_socket.recvfrom(server_port))
#             send_data_transfer("ping", DNS_IP, DNS_PORT, "ACK", 0, client_socket)
#             break
#     print_log()

def bits_to_header(bits):
	bits = bits.decode()
	seq_num = int(bits[:32], 2)
	ack_num = int(bits[32:64], 2)
	syn = int(bits[64], 2)
	ack = int(bits[65], 2)
	return TCP_header(seq_num, ack_num, syn, ack)
