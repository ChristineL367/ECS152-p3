import sys
import socket
import binascii
import threading
import time
import random

log = []
data_sent = 0


class TCP_header():

    def __init__(self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port=53):
        self.source_prt = src_port  # 16 bits
        self.destination_prt = dst_port  # 16 bits
        self.sequence_num = seq_num  # 32 bits
        self.ACK_num = ack_num  # 32 bits
        # self.header_length = 0 # 4 bits
        self.unused = 0  # 4 bits
        self.CWR = 0  # 1 bit
        #self.ECE = 0  # 1 bit
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

    def get_bits(self):
        bits = '{0:016b}'.format(self.source_prt)
        bits += '{0:016b}'.format(self.destination_prt)
        bits += '{0:032b}'.format(self.sequence_num)
        bits += '{0:032b}'.format(self.ACK_num)
        bits += '{0:04b}'.format(self.unused)
        bits += '{0:01b}'.format(self.CWR)
        #bits += '{0:01b}'.format(self.ECE)
        bits += '{0:01b}'.format(self.SYN)
        bits += '{0:01b}'.format(self.ACK)
        bits += '{0:01b}'.format(self.FIN)
        if self.data != "":
            for x in self.data:
                bits += format(ord(x), '08b')
        return bits.encode()

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
        elif self.data != "":
            return "DATA"


class Client():
    def __init__(self):
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.client_sock.bind(("127.0.0.1", 0))
        self.connection = False
        self.data_port = 53
        self.timeout = 1
        self.SRTT = 0
        self.RTTVAR = 0
        self.rtts = []
        self.rrts_dev = []
        self.packet_losses = 0
        self.packets_sent = 0
        self.data_sent = 0
        # self.client_sock.settimeout(self.timeout)

    def handshake(self, address, port):

        global log

        try:
            # first handshake (self, dst_port, seq_num, ack_num, syn, ack, fin, data, src_port = 53
            message_syn = TCP_header(port, int(random.uniform(0, 4294967295)), 0, 0, 0, 0, "")
            message_syn.custom_message(0, 1, 0)

            curr_seq = 0
            curr_ack = 0

            log.append([self.client_sock.getsockname()[1], port, "SYN", len(message_syn.get_bits()), time.time()])            
            while (1):
                self.packets_sent += 1
                self.data_sent +=104
                start = time.perf_counter()

                self.client_sock.sendto(message_syn.get_bits(), (address, port))

                try:
                    # receive second handshake
                    self.client_sock.settimeout(self.timeout)
                    data, addr = self.client_sock.recvfrom(1024)
                    self.client_sock.settimeout(None)
                    end = time.perf_counter()
                    # VERY FIRST RTT VALUE WE GET!
                    self.SRTT = end-start
                    self.RTTVAR = self.SRTT / 2
                    self.timeout = self.SRTT + max(6, 4 * self.RTTVAR)
                    break
                except socket.timeout:
                    end = time.perf_counter()
                    # VERY FIRST RTT VALUE WE GET!
                    self.SRTT = end - start
                    self.RTTVAR = self.SRTT / 2
                    self.timeout = self.SRTT + max(6, 4 * self.RTTVAR)
                    self.packet_losses += 1

                    continue

            # time.sleep(3)
            print("get synack")
            message_synack = bits_to_header(data)

            data_port = message_synack.destination_prt
            self.data_port = data_port

            curr_seq = message_synack.ACK_num
            curr_ack = message_synack.sequence_num

            if message_synack.FIN == 1:
                log.append([port, self.client_sock.getsockname()[1], "FIN", len(message_synack.get_bits()), time.time()])
                self.closeconnection(1, message_synack.ACK_num, message_synack.sequence_num + 1, address, port)

            if (message_synack.SYN == 1 and message_synack.ACK == 1):
                # send third handshake
                print("check synack")
                self.connection = True
                message_ack = TCP_header(port, message_synack.ACK_num, message_synack.sequence_num + 1, 0, 0, 0, "")
                message_ack.custom_message(1, 0, 0)

                log.append([port, self.client_sock.getsockname()[1], "SYNACK", len(message_synack.get_bits()), time.time()])
                log.append([self.client_sock.getsockname()[1], port, "ACK", len(message_ack.get_bits()), time.time()])

                self.data_sent +=104
                self.client_sock.sendto(message_ack.get_bits(), (address, port))

                return [message_ack.ACK_num, message_synack.sequence_num + 1]

            return ""
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, curr_seq, curr_ack, address, port)

    def udpconnect(self, prev_message, address, port, file):

        global log

        cur_seq = prev_message[0]
        cur_ack = prev_message[1]

        file_text = open(file, "r")
        not_eof = True

        try:
            while self.connection:
                print("in udp connect")

                file_read = file_text.read(987)
                if not file_read:
                    print("End Of File")
                    not_eof = False
                    break

                message = TCP_header(port, cur_seq, cur_ack, 0, 0, 0, file_read)

                log.append([self.client_sock.getsockname()[1], port, "DATA", len(message.get_bits()), time.time()])
                # self.client_sock.settimeout(self.timeout)
                while (1):
                    self.packets_sent += 1
                    self.data_sent +=8000
                    start = time.perf_counter()

                    self.client_sock.sendto(message.get_bits(), (address, port))

                    self.packets_sent += 1
                    self.client_sock.settimeout(self.timeout)
                    try:

                        data, addr = self.client_sock.recvfrom(1024)
                        self.client_sock.settimeout(None)
                        end = time.perf_counter()
                        new_est = (1 - .125) * self.SRTT + .125 * (end-start)
                        new_dev = (1 - .25) * self.RTTVAR + .25 * abs(self.SRTT - ((end-start) / 2))
                        self.SRTT = new_est

                        self.RTTVAR = new_dev
                        self.timeout = self.SRTT + 4 * self.RTTVAR
                        if self.timeout < 1:
                            self.timeout = 1
                        # self.client_sock.settimeout(self.timeout)
                        message = bits_to_header(data)
                        cur_seq = message.ACK_num
                        cur_ack = message.sequence_num

                        if message.get_type() != "ACK":
                            continue

                        if message.FIN == 1:
                            log.append([port, self.client_sock.getsockname()[1], "FIN", len(message.get_bits()), time.time()])
                            file_text.close()
                            self.closeconnection(1, cur_seq, cur_ack + 1, address, port)
                            break

                        if message.ACK == 1:
                            print(data)
                            log.append([port, self.client_sock.getsockname()[1], "FIN", len(message.get_bits()), time.time()])
                            cur_seq = message.ACK_num
                            cur_ack = 1 + message.sequence_num
                            break

                        break
                    except socket.timeout:
                        # self.timeout +=1
                        end = time.perf_counter()
                        new_est = (1 - .125) * self.SRTT + .125 * (end - start)
                        new_dev = (1 - .25) * self.RTTVAR + .25 * abs(self.SRTT - ((end - start) / 2))
                        self.SRTT = new_est

                        self.RTTVAR = new_dev
                        self.timeout = self.SRTT + 4 * self.RTTVAR
                        if self.timeout < 1:
                            self.timeout = 1
                        self.packet_losses += 1
                        #print("RESEND")
                        continue

                if message.FIN == 1:
                    break

            file_text.close()
            self.closeconnection(0, cur_seq, cur_ack, address, port)

        except KeyboardInterrupt:
            print("Keyboard Interruption")
            file_text.close()
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
                print("FIN: ",message.FIN)
                self.data_sent +=104
                self.client_sock.sendto(message.get_bits(), (address, port))

                data, addr = self.client_sock.recvfrom(1024)
                message = bits_to_header(data)

                if message.ACK == 1:
                    log.append([port, self.client_sock.getsockname()[1], "ACK", len(message.get_bits()), time.time()])
                    break

        elif putah == 1:
            message = TCP_header(port, cur_seq, cur_ack, 0, 1, 0, "")

            log.append([self.client_sock.getsockname()[1], port, "ACK", len(message.get_bits()), time.time()])
            self.data_sent += 104
            self.client_sock.sendto(message.get_bits(), (address, port))

        print("connection closed")
        self.connection = 0
        self.client_sock.close()


def bits_to_header(bits):
    bits = bits.decode()
    src_port = int(bits[:16], 2)
    dst_port = int(bits[16:32], 2)
    seq_num = int(bits[32:64], 2)
    ack_num = int(bits[64:96], 2)
    unused = int(bits[96:100], 2)
    cwr = int(bits[100], 2)
    #ece = int(bits[101], 2)
    print("in bits_to_header", ack_num)
    syn = int(bits[101], 2)
    print(syn)
    ack = int(bits[102], 2)
    fin = int(bits[103], 2)
    print("in bits to header 1")
    try:
        data_string = bits[104:]
        data = ""
        length = len(data_string) / 8

        for x in range(int(length)):
            start = x * 8
            end = (x + 1) * 8
            data += chr(int(str(data_string[start:end]), 2))
    except:
        data = ""
    return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, data, src_port)

def writetofile(port):
    file_name = str(port) + "_solano.txt"
    with open(file_name, 'w') as f:
         for i in range(0, len(log)):
            f.write(str(log[i][0]) + " | " + str(log[i][1]) + " | "+ str(log[i][2])+ " | " + str(log[i][3]) + " | " + str(log[i][4]) + "\n")

if __name__ == '__main__':
    server_ip = sys.argv[2]
    port = int(sys.argv[4])
    file = sys.argv[6]
    client = Client()

    handshake_message = client.handshake(server_ip, port)

    if client.connection == True and handshake_message != "":
        start = time.perf_counter()
        client.udpconnect(handshake_message, server_ip, client.data_port, file)
        end = time.perf_counter()
        time_elapsed = end-start
        print("Time to send file (seconds)s:", time_elapsed)
        bandwidth = client.data_sent/time_elapsed
        print("Bandwidth achieved (bits/second):", bandwidth)
        percent = client.packet_losses*100 / client.packets_sent
        print("Packet loss percent:", percent)

    writetofile(client.data_port)

# handshake:

# client: s=0 a=0  server: s=0, a=1
# client: s=1, a=1
# client: s=1 a=1 server: s=1 a=5
# cleint: s=5 a=5 server: s=5 a=9
# client: s=9 a=9

#python3 sender_solano.py --ip 127.0.0.1 --dest_port 32007 --input alice29.txt