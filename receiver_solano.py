from pickle import FALSE, TRUE
import sys
import threading
from threading import Thread
import socket
import binascii
import time
import random
log = []
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
class Server():
    def __init__(self, server_port):
        self.server_port = int(server_port)
        self.connections = [] #queue
        self.welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.welcome_socket.bind(('127.0.0.1', self.server_port))
        self.curconnection = None

        #self.lock = threading.Lock()

    def send_packet(self,message, DNS_IP, DNS_PORT, socket_obj, jitter):
        READ_BUFFER = 1024  # size of the buffer to read in the received UDP packet.

        address = (DNS_IP, DNS_PORT)

        our_socket = socket_obj  # Internet, UDP.
        # send message to given address

        print(message)
        time.sleep(jitter)

        our_socket.sendto(message, address)
        #logger(53, DNS_PORT, type, length)
        # receive message

        #our_socket.close()
    def handshake(self, connection, packet_loss, jitter): #basically accept
        #self.welcome_socket.listen() #put this in main

        try:
            while(1):
                packet, address = self.welcome_socket.recvfrom(1024) #check this size
                x = random.randrange(0,100)
                if x <= packet_loss:
                    continue
                print("handshake get SYN: ", packet)
                message_syn = self.bits_to_header(packet)

                print(message_syn.SYN)

                cur_seq = message_syn.ACK_num
                cur_ack = message_syn.sequence_num

                if message_syn.get_type() == "FIN":
                    self.welcoming_closeconnection(0, cur_seq, cur_ack,address[0], address[1], self.welcome_socket.getsockname()[1])
                    return 0

                if message_syn.get_type() == "SYN":
                    print("got syn")
                    print(address)
                    connection.data_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    connection.data_port.bind(("127.0.0.1", 0))

                    print(connection.data_port.getsockname()[1])
                    synack = TCP_header(connection.data_port.getsockname()[1], 0, message_syn.sequence_num+1,0,0,0,"", self.server_port)
                    synack.custom_message(1,1,0)

                    connection.got_syn = 1
                    log.append([address[0], address[1], "SYNACK", len(synack.get_bits())])
                    jit = random.uniform(0, 1)
                    if jit >= jitter:

                        self.send_packet(synack.get_bits(), address[0], address[1], self.welcome_socket, jit)
                    else:
                        self.send_packet(synack.get_bits(), address[0], address[1], self.welcome_socket, 0)

                packet2, address2 = self.welcome_socket.recvfrom(1024)
                x = random.randrange(0, 100)
                if x <= packet_loss:
                    continue
                message2 = self.bits_to_header(packet2)

                cur_seq = message2.ACK_num
                cur_ack = message2.sequence_num

                if message2.get_type() == "FIN":
                    print("interruption")
                    self.welcoming_closeconnection(0, cur_seq, cur_ack,address[0], address[1], self.welcome_socket.getsockname()[1])
                    return 0

                if message2.get_type() == "ACK" and connection.got_syn == 1:
                    print("check ack")
                    connection.got_ack = 1
                    connection.connected = 1

                    self.connections.append(connection)
                    self.curconnection = connection
                    return 1
                else:
                    print("Couldn't establish handshake...")
                    return 0

        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.welcoming_closeconnection(1, cur_seq, cur_ack,address[0], address[1], self.welcome_socket.getsockname()[1])
            return 0

    def data(self, packet_loss, jitter):

            #separate from welcome thread
        try:
            while (1):
                # try:
                        #self.data_socket.listen()
                packet, address = self.curconnection.data_port.recvfrom(1024)# check this size
                x = random.randrange(0, 100)
                if x <= packet_loss:
                    continue
                message = self.bits_to_header(packet)
                cur_seq = message.ACK_num
                cur_ack = message.sequence_num
                if message.get_type() == "FIN":
                    self.data_closeconnection(0, cur_seq, cur_ack, address[0], address[1], self.curconnection.data_port.getsockname()[1])  # figure out how to end the connection here
                    break
                print("packet length: ", packet)
                print("oacket", packet)
                print("message", message.data)
                print("message length: ", len(message.data))

                bits = len(packet.decode())

                print("received: ack:", message.ACK_num, " sequence: ", message.sequence_num)

                print("break")

                #time.sleep(3)

                response = TCP_header(address[1], message.ACK_num, message.sequence_num+bits, 0, 1, 0, "", self.curconnection.data_port.getsockname()[1])
                packet = response.get_bits()

                print("sending: ack:", message.sequence_num+bits, " sequence: ", message.ACK_num)

                log.append([address[0], address[1], "DATA", len(packet)])
                jit = random.uniform(0, 1)
                # send ACK and add jitter
                if jit >= jitter:

                    self.send_packet(packet, address[0], address[1], self.curconnection.data_port, jit)
                else:
                    self.send_packet(packet, address[0], address[1], self.curconnection.data_port, 0)
                    

        except KeyboardInterrupt:
            print("Server Keyboard Interruption")
            self.data_closeconnection(1, cur_seq, cur_ack,address[0], address[1], self.curconnection.data_port.getsockname()[1])



    def thread_handshake(self, connection):
        t = threading.Thread(target=self.handshake(connection)) #create new thread for a new client connection
        t.daemon = True
        t.start()
    
    # def logger(source, dest, type, length):
    #     log.append([source, dest, type, length])


    def bits_to_header(self, bits):
        bits = bits.decode()
        src_port = int(bits[:16], 2)
        dst_port = int(bits[16:32], 2)
        seq_num = int(bits[32:64], 2)
        ack_num = int(bits[64:96], 2)
        print("in bits_to_header", ack_num)
        syn = int(bits[96], 2)
        print(syn)
        ack = int(bits[97], 2)
        fin = int(bits[98], 2)
        print("in bits to header 1")
        try:
            data_string = bits[99:]
            print("data_string: ", data_string)
            num = len(data_string)/8 
            data = ""

            for x in range(int(num)):
                start = x*8
                end = (x+1)*8
                data += chr(int(str(data_string[start:end]),2))
            print(data)
        except:
            data = ""
        return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, data, src_port)
    
    def welcoming_closeconnection(self, putah, cur_seq, cur_ack,address, dst_port, src_port):
        if putah == 1:
            ack = False
            while ack != True:
                message = TCP_header(dst_port,cur_seq, cur_ack+1,0,0,0, "", src_port)
                message.FIN = 1

                log.append([address, dst_port, "FIN", len(message.get_bits())])
                self.welcome_socket.sendto(message.get_bits(), (address, dst_port))

                data, addr = self.welcome_socket.recvfrom(1024)
                message = self.bits_to_header(data)

                if message.ACK == 1:
                    break
        elif putah == 0:
            message = TCP_header(dst_port,cur_seq, cur_ack+1,0,0,0, "", src_port)  
            message.ACK = 1

            log.append([address, dst_port, "ACK", len(message.get_bits())])
            self.welcome_socket.sendto(message.get_bits(), (address, dst_port))

        print("closing connection for port ")
        self.welcome_socket.close()
        self.welcome_socket.closed = 1
    def data_closeconnection(self, putah, cur_seq, cur_ack, address, dst_port, src_port):

        # putah = 0 -> client initiated close
        # putah = 1 -> server initiated close
        # putah = 2 -> wrong data
        if putah == 1:
            ack = False
            count = 0
            while ack != True or count != 3:
                message = TCP_header(dst_port,cur_seq, cur_ack+1,0,0,0, "", src_port)
                message.FIN = 1

                print("in data fin")
                log.append([address, dst_port, "FIN", len(message.get_bits())])
                self.curconnection.data_port.sendto(message.get_bits(), (address, dst_port))

                data, addr = self.curconnection.data_port.recvfrom(1024)
                message = self.bits_to_header(data)
                print("ack in fin", message.ACK)

                if message.ACK == 1:
                    break
                count += 1
        elif putah == 0:
            message = TCP_header(dst_port,cur_seq, cur_ack+1,0,0,0, "", src_port)  
            message.ACK = 1

            log.append([address, dst_port, "ACK", len(message.get_bits())])
            self.curconnection.data_port.sendto(message.get_bits(), (address, dst_port))

        print("closing connection for port ")
        self.curconnection.data_port.close()
        self.curconnection.closed = 1
class handshakeThread(Thread):
    def __init__(self, client_ip, port, server_init, jitter, packet_loss):
        Thread.__init__(self)
        self.client_ip = client_ip
        self.port = port
        self.server_init = server_init
        self.handshaken = 0
        self.threads = []
        self.jitter = jitter
        self.packet_loss = packet_loss
    def run(self):

        while True:
            new_connection = connection()

            self.server_init.handshake(new_connection, self.jitter, self.packet_loss)

            if new_connection.connected == 1:
                print("connected to new client")
                self.handshaken= 1
                new_data = dataThread(self.server_init, self.jitter, self.packet_loss)
                new_data.start()
                self.threads.append(new_data)
                if self.server_init.curconnection.closed == 1:
                    new_data.join()

class dataThread(Thread):
    def __init__(self, server_init, jitter, packet_loss):
        Thread.__init__(self)
        self.server_init = server_init
        self.jitter = jitter
        self.packet_loss = packet_loss
    def run(self):

        self.server_init.data(self.jitter, self.packet_loss)
if __name__ == '__main__':
    client_ip = sys.argv[2]
    port = sys.argv[4]
    packet_loss = int(sys.argv[6])
    jitter = float(sys.argv[8])
    server_init = Server(sys.argv[4])
    #new_connection = connection()#will enventually be multithreaded
    new_thread = handshakeThread(client_ip, port, server_init, packet_loss, jitter)  # will enventually be multithreaded
    # server_init.thread_data()
    new_thread.start()

    new_thread.join()


    for i in range(0,len(log)):
       print(log[i][0] , " | " , log[i][1] , " | " , log[i][2] , " | " , log[i][3])

#python3 client_putah.py --server_ip 127.0.0.1 --server_port 32007
#python3 server_putah.py --ip 127.0.0.1 --port 32007