from pickle import FALSE, TRUE
import sys
import threading
import socket
import binascii
import time
log = []
class connection():
    def __init__(self):
        self.connected = 0
        self.client_ip = None
        self.client_port = None
        self.got_syn = 0
        self.got_ack = 0
        self.message = None
class TCP_header():
    def __init__(self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port):
        self.source_prt = 0  # 16 bits
        self.destination_prt = 0 # 16 bits
        self.sequence_num = 0  # 32 bits
        self.ACK_num = 0 # 32 bits
        # self.header_length = 0 # 4 bits
        # self.unused = 0 # 4 bits
        # self.CWR = 0 # 1 bit
        # self.ECE = 0 # 1 bit
        # self.URG = 0 # 1 bit
        self.ACK = 0  # ack flag 0 if not ack, 1 if syn-ack or ack
        # self.PSH = 0 # 1 bit
        # self.RST = 0 # 1 bit
        self.SYN = 0  # syn flag 0 if not syn, 1 if syn-ack or syn
        self.FIN = 0 # 1 bit
        # self.receive_window = 0 # 16 bits
        # self.internet_checksum = 0 # 16 bits
        # self.urgent_data_ptr = 0 # 16 bits
        # self.options = 0
        self.data = ""
    def get_bits(self):
        bits = '{0:016b}'.format(self.source_prt)
        bits += '{0:016b}'.format(self.destination_prt)
        bits = '{0:032b}'.format(self.seq_num)
        bits += '{0:032b}'.format(self.ack_num)
        bits += '{0:01b}'.format(self.syn)
        bits += '{0:01b}'.format(self.ack)
        bits += bin(int(binascii.hexlify('data'), 16))
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
        elif self.data == "":
            return "DATA"
class Server():
    def __init__(self, server_port):
        self.server_port = server_port
        self.connections = [] #queue
        self.welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.welcome_socket.bind(("127.0.01", server_port))
        self.curconnection = None

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
        self.welcome_socket.listen() #put this in main

        packet, address = self.welcome_socket.recvfrom(1024) #check this size
        message = self.bits_to_header(packet)
        if message.get_type() == "FIN":
            self.closeconnection(0, address, 53)
        if message.get_type() == "SYN":
            connection.data_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            connection.data_port.bind("127.0.01", 0)
            synack = TCP_header(connection.data_port, 0,0,0,0,0,0, "", self.server_port)
            synack.custom_message(1,1,0)


            connection.got_syn = 1
            self.send_packet(synack.get_bits(), address, 53, self.welcome_socket)
        time.sleep(4)
        packet2, address2 = self.welcome_socket.recvfrom(1024)
        message2 = self.bits_to_header(packet2)
        if message2.get_type() == "ACK" and connection.got_syn == 1:
            connection.got_ack = 1
            connection.connected = 1

            self.connections.append(connection)
            self.curconnection = connection
            return 1
        else:
            print("Couldn't establish handshake...")
            return 0
    def data(self):

            #separate from welcome thread

        while (1):
            try:
                if packet.get_type() == "FIN":
                    break
                else:
                    self.data_socket.listen()
                    packet, address = self.welcome_socket.recvfrom(1024)  # check this size
                    message = self.bits_to_header(packet)
                    if message.get_type() == "FIN":
                        self.closeconnection(0, address, 53)  # figure out how to end the connection here
                    else:
                        response = TCP_header(53, 0, 0, 0, 0, 0, 0, "pong", self.curconnection.dataport)
                        packet = response.get_bits()
                        self.send_packet(packet, address, 53, self.curconnection.dataport)

            except KeyboardInterrupt:
                print("Keyboard Interruption")
                self.closeconnection(1, "127.0.0.1",self.curconnection.dataport)



    def thread_handshake(self, connection):
        t = threading.Thread(target=self.handshake(connection)) #create new thread for a new client connection
        t.daemon = True
        t.start()
    def logger(source, dest, type, length):
        log.append([source, dest, type, length])


    def bits_to_header(bits):
        bits = bits.decode()
        src_port = int(bits[:16], 2)
        dst_port = int(bits[16:32], 2)
        seq_num = int(bits[32:64], 2)
        ack_num = int(bits[64:96], 2)
        syn = int(bits[97], 2)
        ack = int(bits[98], 2)
        fin = int(bits[99], 2)
        data = bits[99:]
        data_string = binascii.unhexlify('%x' % data)

        return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, data_string, src_port)
    def closeconnection(self, putah, address, port):

        # putah = 0 -> client initiated close
        # putah = 1 -> server initiated close
        # putah = 2 -> wrong data
        if putah == 1:
            ack = False
            while ack != True:
                message = TCP_header()
                message.ACK = 1
                self.socket.sendto(message.get_bits(), (address, port))

                data, addr = self.socket.recvfrom(1024)
                message = self.bits_to_header(data)

                if message.ACK == 1:
                    break
        elif putah == 0:
            message = TCP_header()
            message.FIN = 1
            self.socket.sendto(message.get_bits(), (address, port))
        self.socket.close()
if __name__ == '__main__':
    client_ip = sys.argv[2]
    port = sys.argv[4]
    server_init = Server(sys.argv[4])
    new_connection = connection() #will enventually be multithreaded
    server_init.handshake(connection)
    if new_connection.connected == 1:
        server_init.data()