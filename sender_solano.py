import sys
import socket
import binascii
import threading
import time

log = []
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
            for x in self.data:
                    bits += format(ord(x), '08b')
        return bits.encode()


class Client():
    def __init__(self):
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind(("127.0.0.1", 0))
        self.connection = False
        self.data_port = 53
    
    def handshake(self, address, port):
        
        global log

        try:
        # first handshake (self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53
            message_syn = TCP_header(port,0,0,0,0,0, "")
            message_syn.custom_message(0,1,0)

            curr_seq = 0
            curr_ack = 0

            print("start handshake")
            log.append([address, port, "SYN", len(message_syn.get_bits())])
            self.client_sock.sendto(message_syn.get_bits(), (address, port))

            # receive second handshake
            data, addr = self.client_sock.recvfrom(1024)
            time.sleep(3)
            print("get synack")
            message_synack = bits_to_header(data)

            data_port = message_synack.destination_prt
            self.data_port = data_port

            curr_seq = message_synack.ACK_num
            curr_ack = message_synack.sequence_num

            if message_synack.FIN == 1:
                self.closeconnection(1, message_synack.ACK_num, message_synack.sequence_num, address, port)
                
            
            if(message_synack.SYN == 1 and message_synack.ACK == 1):
                # send third handshake
                print("check synack")
                self.connection = True
                message_ack = TCP_header(port,message_synack.ACK_num, message_synack.sequence_num+1,0,0,0, "")
                message_ack.custom_message(1,0,0)

                log.append([address, port, "ACK", len(message_ack.get_bits())])
                self.client_sock.sendto(message_ack.get_bits(), (address, port))
                return [message_ack.ACK_num, message_synack.sequence_num+1]
            
            return ""
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, curr_seq, curr_ack, address, port)
            
    def udpconnect(self, prev_message, address, port):

        global log

        cur_seq = prev_message[0]
        cur_ack = prev_message[1]

        try:
            while self.connection:
                print("in udp connect")
                message = TCP_header(port,cur_seq,cur_ack,0,0,0, "Ping")

                print("sending", "seq: ", message.sequence_num, "ack: ", message. ACK_num)
                temp = message.get_bits()
                print(message.get_bits())
                print("message length: ", len(message.get_bits()))

                temp = bits_to_header(temp)
                print(temp.ACK_num, temp.sequence_num)

                print("break")
                

                log.append([address, port, "DATA", len(message.get_bits())])
                self.client_sock.sendto(message.get_bits(), (address,port)) 
                data, addr = self.client_sock.recvfrom(1024)

                message = bits_to_header(data)

                print(data)

                print("client: ", message.data, "seq: ", message.sequence_num, "ack: ", message. ACK_num)
                
                if message.FIN == 1:
                    self.closeconnection(1, cur_seq, cur_ack, address, port)
                    break
                
                if message.data == "Pong":
                    cur_seq = message.ACK_num
                    cur_ack = len(message.data) + message.sequence_num
                    time.sleep(3)
                    continue
                else:
                    print("wrong data from server")
                    self.closeconnection(2, cur_seq, cur_ack,  address, port)
                
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0,  cur_seq, cur_ack, address,port)

    def udpconnect_readfile(self, prev_message, address, port, file):
        cur_seq = prev_message[0]
        cur_ack = prev_message[1]

        file_text = open(file, "r")
        not_eof = True

        try:
            while self.connection and not_eof:
                print("in udp connect")

                # read file

                file_read = file_text.read(112)
                if not file_read:
                    print("End Of File")
                    not_eof = False
                    break

                message = TCP_header(port,cur_seq,cur_ack,0,0,0, file_read)
                print("line: ", message.data)


                print("sending", "seq: ", message.sequence_num, "ack: ", message. ACK_num)
                temp = message.get_bits()
                print(message.get_bits())

                temp = bits_to_header(temp)
                print(temp.data)

                print("break")
                

                log.append([address, port, "DATA", len(message.get_bits())])
                self.client_sock.sendto(message.get_bits(), (address,port)) 
                data, addr = self.client_sock.recvfrom(1024)

                message = bits_to_header(data)

                print(data)

                print("client: ", message.data, "seq: ", message.sequence_num, "ack: ", message. ACK_num)
                
                if message.FIN == 1:
                    self.closeconnection(1, cur_seq, cur_ack, address, port)
                    break
                
                if message.ACK == 1:
                    print("received: ack: ", message.ACK_num, " seq: ",message.sequence_num )
                    cur_seq = message.ACK_num
                    cur_ack = 1 + message.sequence_num
                    continue
                else:
                    print("wrong data from server")
                    self.closeconnection(2, cur_seq, cur_ack,  address, port)
            
            file_text.close()
                
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            file_text.close()
            self.closeconnection(0,  cur_seq, cur_ack, address,port)
    
    def closeconnection(self, putah, cur_seq, cur_ack, address, port):

        # putah = 0 -> client initiated close
        # putah = 1 -> server initiated close
        # putah = 2 -> wrong data
        #global log

        if putah == 0:
            ack = False
            count = 0
            while ack != True or count != 3:
                # dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53):
                message = TCP_header(port,cur_seq,cur_ack+1,0,0,1,"")

                log.append([address, port, "FIN", len(message.get_bits())])
                self.client_sock.sendto(message.get_bits(), (address,port)) 

                data, addr = self.client_sock.recvfrom(1024)
                message = bits_to_header(data)

                if message.ACK == 1:
                    break
        
        elif putah == 1:
            message = TCP_header(port,cur_seq,cur_ack+1,0,1,0,"")

            log.append([address, port, "ACK", len(message.get_bits())])
            self.client_sock.sendto(message.get_bits(), (address,port))      
            
        
        print("connection closed")
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
        num = len(data_string)/8 
        data = ""

        for x in range(int(num)):
            start = x*8
            end = (x+1)*8
            data += chr(int(str(data_string[start:end]),2))

    except:
        data = ""

    return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, data, src_port)

def test_reading(file):
    file_text = open(file, "r")
    not_eof = True

    while not_eof:
        file_read = file_text.read()
        if not file_read:
            print("End Of File")
            not_eof = False
            break
        
        bit_string = ""

        for x in file_read:
            bit_string += format(ord(x), '08b')
        
        print(file_read)
        print(bit_string)

    file_text.close()

if __name__ == '__main__':
    server_ip = sys.argv[2]
    port = int(sys.argv[4])
    client = Client()

    handshake_message = client.handshake(server_ip, port)
    print("client connectione established")
    print(client.data_port)
    if client.connection == True and handshake_message != "":
            time.sleep(4)
            client.udpconnect_readfile(handshake_message, server_ip, client.data_port, sys.argv[6])

    for i in range(0,len(log)):
       print(log[i][0] , " | " , log[i][1] , " | " , log[i][2] , " | " , log[i][3])

    # test_reading(sys.argv[1])
            



# handshake:

# client: s=0 a=0  server: s=0, a=1
# client: s=1, a=1 
# client: s=1 a=1 server: s=1 a=5
# cleint: s=5 a=5 server: s=5 a=9
# client: s=9 a=9