import sys
import socket
import binascii
import threading
import time
import random

log = []


class TCP_header():

    def __init__(self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port=53):
        self.source_prt = src_port  # 16 bits
        self.destination_prt = dst_port  # 16 bits
        self.sequence_num = seq_num  # 32 bits
        self.ACK_num = ack_num  # 32 bits
        # self.header_length = 0 # 4 bits
        # self.unused = 0 # 4 bits
        # self.CWR = 0 # 1 bit
        # self.ECE = 0 # 1 bit
        # self.URG = 0 # 1 bit
        self.ACK = ack  # ack flag 0 if not ack, 1 if syn-ack or ack
        # self.PSH = 0 # 1 bit
        # self.RST = 0 # 1 bit
        self.SYN = syn  # syn flag 0 if not syn, 1 if syn-ack or syn
        self.FIN = fin  # 1 bit
        # self.receive_window = 0 # 16 bits
        # self.internet_checksum = 0 # 16 bits
        # self.urgent_data_ptr = 0 # 16 bits
        # self.options = 0
        self.data = data

    def custom_message(self, ack, syn, fin):

        self.ACK = ack  # ack flag 0 if not ack, 1 if syn-ack or ack

        self.SYN = syn  # syn flag 0 if not syn, 1 if syn-ack or syn
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
        bits += '{0:032b}'.format(int(self.sequence_num))
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
        self.client_sock.bind(("127.0.0.1", 0))
        self.connection = False
        self.data_port = 53

    def handshake(self, address, port):

        global log

        try:
            # first handshake (self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53
            message = TCP_header(port, random.uniform(0, 4294967295), 0, 0, 0, 0, "")
            message.custom_message(0, 1, 0)

            cur_seq = 0
            cur_ack = 0

            log.append([self.client_sock.getsockname()[1], port, "SYN", len(message.get_bits()), time.time()])            
            self.client_sock.sendto(message.get_bits(), (address, port))

            # receive second handshake
            data, addr = self.client_sock.recvfrom(1024)
            time.sleep(3)
            message_synack = bits_to_header(data)

            cur_seq = message_synack.ACK_num
            cur_ack = message_synack.sequence_num

            data_port = message_synack.destination_prt
            self.data_port = data_port

            if message_synack.FIN == 1:
                log.append([port, self.client_sock.getsockname()[1], "FIN", len(message_synack.get_bits()), time.time()])
                self.closeconnection(1, cur_seq, cur_ack + 1, address, port)

            if (message_synack.SYN == 1 and message_synack.ACK == 1):
                # send third handshake
                self.connection = True
                message_ack = TCP_header(port, cur_seq, cur_ack + 1, 0, 0, 0, "")
                message_ack.custom_message(1, 0, 0)

                log.append([port, self.client_sock.getsockname()[1], "SYNACK", len(message_synack.get_bits()), time.time()])
                self.client_sock.sendto(message_ack.get_bits(), (address, port))

                log.append([self.client_sock.getsockname()[1], port, "ACK", len(message_ack.get_bits()), time.time()])

                return [message_ack.ACK_num, message_synack.sequence_num + 1]

            return ""

        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, cur_seq, cur_ack, address, port)

    def udpconnect(self, prev_message, address, port):

        global log

        cur_seq = prev_message[0]
        cur_ack = prev_message[1]

        try:
            while self.connection:

                message = TCP_header(port, cur_seq, cur_ack, 0, 0, 0, "Ping")

                log.append([self.client_sock.getsockname()[1], port, "DATA", len(message.get_bits()), time.time()])
                self.client_sock.sendto(message.get_bits(), (address, port))
                data, addr = self.client_sock.recvfrom(1024)

                message = bits_to_header(data)
                cur_seq = message.ACK_num
                cur_ack = len(message.data) + message.sequence_num


                if message.FIN == 1:
                    log.append([port, self.client_sock.getsockname()[1], "FIN", len(message.get_bits()), time.time()])
                    self.closeconnection(1, cur_seq, cur_ack + 1, address, port)
                    break
           
                if message.data == "Pong":
                    time.sleep(2)
                    log.append([port, self.client_sock.getsockname()[1], "DATA", len(message.get_bits()), time.time()])
                    continue
                else:
                    print("wrong data from server")
                    self.closeconnection(2, cur_seq, cur_ack, address, port)

        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, cur_seq, cur_ack, address, port)

    def closeconnection(self, putah, cur_seq, cur_ack, address, port):

        # putah = 0 -> client initiated close
        # putah = 1 -> server initiated close
        # putah = 2 -> wrong data
        # global log

        if putah == 0:
            ack = False
            count = 0
            while ack != True or count != 3:
                # dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53):
                message = TCP_header(port, cur_seq, cur_ack, 0, 0, 1, "")

                log.append([self.client_sock.getsockname()[1], port, "FIN", len(message.get_bits()), time.time()])
                self.client_sock.sendto(message.get_bits(), (address, port))
                

                data, addr = self.client_sock.recvfrom(1024)
                message = bits_to_header(data)

                if message.ACK == 1:
                    log.append([port, self.client_sock.getsockname()[1], "ACK", len(message.get_bits()), time.time()])
                    break

        elif putah == 1:
            message = TCP_header(port, cur_seq, cur_ack, 0, 1, 0, "")

            log.append([self.client_sock.getsockname()[1], port, "ACK", len(message.get_bits()), time.time()])
            self.client_sock.sendto(message.get_bits(), (address, port))

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

def writetofile(port):
    file_name = str(port) + "_putah.txt"
    with open(file_name, 'w') as f:
         for i in range(0, len(log)):
            f.write(str(log[i][0]) + " | " + str(log[i][1]) + " | "+ str(log[i][2])+ " | " + str(log[i][3]) + " | " + str(log[i][4]) + "\n")

if __name__ == '__main__':
    server_ip = sys.argv[2]
    port = int(sys.argv[4])
    client = Client()

    input = client.handshake(server_ip, port)
    if client.connection == True:
        time.sleep(4)
        client.udpconnect(input, server_ip, client.data_port)

    writetofile(client.data_port)