
import sys
import socket
import binascii
import threading
import time

#log = {}
class TCP_header():

    def __init__(self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53):
        self.source_prt = src_port # 16 bits
        self.destination_prt = dst_port # 16 bits
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
        self.data = data

    
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
        bits += '{0:032b}'.format(self.sequence_num)
        bits += '{0:032b}'.format(self.ACK_num)
        bits += '{0:01b}'.format(self.SYN)
        bits += '{0:01b}'.format(self.ACK)
        bits += '{0:01b}'.format(self.FIN)
        if self.data != "":

            bits += self.data
        return bits.encode()


class Client():
    def __init__(self):
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind(("127.0.0.1", 2000))
        self.connection = False
        self.data_port = 53
    
    def handshake(self, address, port):
        
        #global log
        try:
        # first handshake (self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53
            message = TCP_header(port,0,0,0,0,0, "")
            message.custom_message(0,1,0)

            print("start handshake")
            #log[address].append([port, "SYN", len(message.get_bits())])
            self.client_sock.sendto(message.get_bits(), (address, port))

            # receive second handshake
            data, addr = self.client_sock.recvfrom(1024)

            print("get synack")
            message = bits_to_header(data)

            data_port = message.destination_prt
            self.data_port = data_port

            if message.FIN == 1:
                self.closeconnection(1, address, port)
                
            
            if(message.SYN == 1 and message.ACK == 1):
                # send third handshake
                print("check synack")
                self.connection = True
                message = TCP_header(port,0,0,0,0,0, "")
                message.custom_message(1,0,0)

                #log[address].append([port, "ACK", len(message.get_bits())])
                self.client_sock.sendto(message.get_bits(), (address, port))

        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, address,port)
            
    def udpconnect(self, address, port):

        #global log

        try:
            while self.connection:
                print("in udp connect")
                message = TCP_header(port,0,0,0,0,0, "Ping")

                #log[address].append([port, "DATA", len(message.get_bits())])
                self.client_sock.sendto(message.get_bits(), (address,port)) 
                data, addr = self.client_sock.recvfrom(1024)

                message = bits_to_header(data)

                print("client: ", message.data)
                
                if message.FIN == 1:
                    self.closeconnection(1, address, port)
                
                if message.data == "Pong":
                    time.sleep(2)
                    continue
                else:
                    print("wrong data from server")
                    self.closeconnection(2, address, port)
                
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, address,port)
    
    def closeconnection(self, putah, address, port):

        # putah = 0 -> client initiated close
        # putah = 1 -> server initiated close
        # putah = 2 -> wrong data
        #global log

        if putah == 0:
            ack = False
            while ack != True:
                # dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53):
                message = TCP_header(port,0,0,0,0,1,"")

                #log[address].append([port, "FIN", len(message.get_bits())])
                self.client_sock.sendto(message.get_bits(), (address,port)) 

                data, addr = self.client_sock.recvfrom(1024)
                message = bits_to_header(data)

                if message.ACK == 1:
                    break
        
        elif putah == 1:
            message = TCP_header(port,0,0,0,1,0,"")
            self.client_sock.sendto(message.get_bits(), (address,port))      
            
        
        self.connection == 0
        self.client_sock.close()

def bits_to_header(bits):
    bits = bits.decode()
    src_port = int(bits[:16], 2)
    dst_port = int(bits[16:32], 2)
    seq_num = int(bits[32:64], 2)
    ack_num = int(bits[64:96], 2)
    syn = int(bits[96], 2)
    ack = int(bits[97], 2)
    fin = int(bits[98], 2)
    try:
        data_string = bits[99:]
    except:
        data_string = ""

    return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, data_string, src_port)


if __name__ == '__main__':
    server_ip = sys.argv[2]
    port = int(sys.argv[4])
    client = Client()

    client.handshake(server_ip, port)
    print("client connectione established")
    print(client.data_port)
    if client.connection == True:
            time.sleep(4)
            client.udpconnect(server_ip, client.data_port)

    #for key in log:
    #    print(key + " | " + log[key][0] + " | " + log[key][1] + " | " + log[key][2])
            




        















    




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

