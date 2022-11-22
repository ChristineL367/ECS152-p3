import sys
import socket
import binascii
import threading
import time
import math
import matplotlib.pyplot as plt
import numpy as np

log = []
data_sent = 0
global window_sizes
window_sizes = []


class TCP_header():

    def __init__(self, dst_port, seq_num, ack_num, syn, ack, fin, recvw, data, src_port=53):
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
        self.receive_window = recvw # 16 bits
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
        bits += '{0:016b}'.format(self.receive_window)
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
            # first handshake (self, dst_port, seq_num, ack_num, syn, ack, fin, receive_window, data, src_port = 53
            message_syn = TCP_header(port, 0, 0, 0, 0, 0, 1,"")
            message_syn.custom_message(0, 1, 0)

            curr_seq = 0
            curr_ack = 0

            log.append([self.client_sock.getsockname()[1], port, "SYN", len(message_syn.get_bits()), message_syn.receive_window, time.time()])
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
                    self.timeout = self.SRTT + max(6.0, 4 * self.RTTVAR)
                    break
                except socket.timeout: #packet loss or double ack
                    end = time.perf_counter()

                    # VERY FIRST RTT VALUE WE GET!
                    self.SRTT = end - start
                    self.RTTVAR = self.SRTT / 2
                    self.timeout = self.SRTT + max(6.0, 4 * self.RTTVAR)
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
                log.append([port, self.client_sock.getsockname()[1], "FIN", len(message_synack.get_bits()),
                            message_synack.receive_window , time.time()])

                self.closeconnection(1, message_synack.ACK_num, message_synack.sequence_num + 1, address, port)

            if (message_synack.SYN == 1 and message_synack.ACK == 1):
                # send third handshake
                print("check synack")
                self.connection = True
                message_ack = TCP_header(port, message_synack.ACK_num, message_synack.sequence_num + 1, 0, 0, 0, 1, "")
                message_ack.custom_message(1, 0, 0)

                log.append([port, self.client_sock.getsockname()[1], "SYNACK", len(message_synack.get_bits()), message_synack.receive_window, time.time()])
                log.append([self.client_sock.getsockname()[1], port, "ACK", len(message_ack.get_bits()), message_ack.receive_window, time.time()])

                self.data_sent +=104
                self.client_sock.sendto(message_ack.get_bits(), (address, port))

                return [message_ack.ACK_num, message_synack.sequence_num + 1]

            return ""
        except KeyboardInterrupt:
            print("Keyboard Interruption")
            self.closeconnection(0, curr_seq, curr_ack, address, port)

    def udpconnect(self, prev_message, address, port, file, tcp_vers):
        file_data = {}
        global log
        global ssthreshold
        ssthreshold = 16
        acks = [] #list of acks to detect duplicate acks
        cur_seq = prev_message[0]
        cur_ack = prev_message[1]

        window = 1 # from input

        file_text = open(file, "r")
        not_eof = True

        pts = []
        temp = None
        tcp_change = 0

        try:
            while self.connection and not_eof == True:
                print("in udp connect")

                tracker = len(pts)
                if tracker != 0:
                    cur_seq = pts[len(pts)-1] + 1000

                window_sizes.append(window)
                while(len(pts) < window and not_eof == True):
                    print("in loop")
                    if cur_seq in file_data:
                        message = file_data[cur_seq]
                        #message.receive_window = window
                        pts.append(cur_seq)
                        cur_seq += 1000
                        tracker += 1
                        continue

                    file_read = file_text.read(985)
                    
                    if not file_read:
                        print("End Of File")
                        not_eof = False
                        break

                    file_data[cur_seq] = file_read #dictionary of file data that we sent corresponding to its sequence num
                    message = TCP_header(port, cur_seq, cur_ack, 0, 0, 0, window, file_read)

                    file_data[cur_seq] = message
    
                    pts.append(cur_seq)
                    cur_seq += 1000
                    tracker += 1

                    log.append([self.client_sock.getsockname()[1], port, "DATA", len(message.get_bits()), message.receive_window, time.time()])
                # self.client_sock.settimeout(self.timeout)
                # print(file_data.keys())
                # print(cur_seq)

                while (1):
                    # self.packets_sent += 1
                    # self.data_sent +=8000 #bandwidth
                    start = time.perf_counter()
                    print("LENGTH PTS:",len(pts))

                    for i in range(len(pts)):
                        
                        packet = file_data[pts[i]]        
                        print("seq: ", packet.sequence_num, "ack: ", packet.ACK_num)          
                        self.client_sock.sendto(packet.get_bits(), (address, port))
                        
                        self.packets_sent += 1
                        self.data_sent +=8000

                    temp = pts
                    pts = []
                    acks_recv = []

                    self.client_sock.settimeout(self.timeout)
                    
                    while True:
                        try:
                            data, addr = self.client_sock.recvfrom(1024)
                            print("GOT DATA", data)
                            
                            end = time.perf_counter()
                            ack_message = bits_to_header(data)
                            cur_seq = ack_message.ACK_num
                            cur_ack = ack_message.sequence_num + 1
                            acks_recv.append(ack_message.ACK_num) #append the ack we got
                            acks.append(ack_message.ACK_num)
                            window = ack_message.receive_window
                            # if len(acks) >=3: #received 3 acks now, can start checking if we lost a packet
                            #     if len(set(acks[(len(acks)-3):len(acks)])) == 1:#got three duplicate acks
                            #     #CREATE OLD PACKET TO SEND AGAIN!!
                            #         print("3 duplicate ACKS, resend packet from 3 packets ago")
                            #         # message.sequence_num = cur_seq - 3000 #take us back to previous lost sequence to resend
                            #         message = file_data[acks[-1]]
                            #         if tcp_vers == "tahoe":
                            #             message.receive_window = 1  # bring window all the way back to 1
                            #             window = 1
                            #         elif tcp_vers == "reno":
                            #             message.receive_window /= 2  # cut window in half
                            #             window = message.receive_window / 2
                            #         tcp_change = 1
                            #         #set new timeout value
                            #         pts.append(message)
                            #         new_est = (1 - .125) * self.SRTT + .125 * (end - start)
                            #         new_dev = (1 - .25) * self.RTTVAR + .25 * abs(self.SRTT - ((end - start) / 2))
                            #         self.SRTT = new_est

                            #         self.RTTVAR = new_dev
                            #         self.timeout = self.SRTT + 4 * self.RTTVAR
                            #         if self.timeout < 1:
                            #             self.timeout = 1

                                    # continue #go back to top of outer while loop this time resending the lost packet
                            # if message.receive_window < ssthreshold:

                            #     message.receive_window *= 2  # double window after 1 RTT if within ssthresh
                            # else:
                            #     ssthreshold /= 2  # cut ssthreshold in half once threshold reached
                            #     message.receive_window += 1  # increment window by 1 after threshhold reached
                            new_est = (1 - .125) * self.SRTT + .125 * (end-start)
                            new_dev = (1 - .25) * self.RTTVAR + .25 * abs(self.SRTT - ((end-start) / 2))
                            self.SRTT = new_est

                            self.RTTVAR = new_dev
                            self.timeout = self.SRTT + 4 * self.RTTVAR
                            if self.timeout < 1:
                                self.timeout = 1

    
                            if ack_message.get_type() != "ACK":
                                print("in not ack")
                                continue

                            if ack_message.FIN == 1:
                                print("in fin")
                                log.append([port, self.client_sock.getsockname()[1], "FIN", len(message.get_bits()), message.receive_window, time.time()])

                                file_text.close()
                                self.closeconnection(1, cur_seq, cur_ack + 1, address, port)
                                break

                            # if message.ACK == 1:
                            #     print(data)
                            #     print("client: ", message.data, "seq: ", message.sequence_num, "ack: ", message.ACK_num)
                            #     print("received: ack: ", message.ACK_num, " seq: ", message.sequence_num)
                            #     cur_seq += ACK_num
                            #     cur_ack = 1 + message.sequence_num
                            #     break
                            log.append([port, self.client_sock.getsockname()[1], "FIN", len(message.get_bits()), message.receive_window, time.time()])

                            self.client_sock.settimeout(self.timeout)

                        except socket.timeout:
                            print("in socket timeout here")
                            break

                    if acks_recv == []:
                        print("in no receive")
                        # set new timeout value
                        if len(temp) == 0:
                            break
                        message = file_data[temp[0]]

                        end = time.perf_counter()
                        if tcp_vers == "tahoe":
                            message.receive_window = 1  # bring window all the way back to 1
                            window = 1
                        elif tcp_vers == "reno":
                            if message.receive_window != 1:
                                message.receive_window /= 2  # cut window in half
                                window = message.receive_window
                        new_est = (1 - .125) * self.SRTT + .125 * (end - start)
                        new_dev = (1 - .25) * self.RTTVAR + .25 * abs(self.SRTT - ((end - start) / 2))
                        self.SRTT = new_est

                        self.RTTVAR = new_dev
                        self.timeout = self.SRTT + 4 * self.RTTVAR
                        if self.timeout < 1:
                            self.timeout = 1
                        self.packet_losses += 1
                        #print("RESEND")
                        pts = [temp[0]]
                        break

                    else:
                        if len(acks) >=3: #received 3 acks now, can start checking if we lost a packet
                            if len(acks_recv) < window:
                                #we got fewer packets than we sent
                                pass

                            if len(set(acks[(len(acks)-3):len(acks)])) == 1:#got three duplicate acks
                            #CREATE OLD PACKET TO SEND AGAIN!!
                                print("3 duplicate ACKS, resend packet from 3 packets ago")
                                # message.sequence_num = cur_seq - 3000 #take us back to previous lost sequence to resend
                                message = file_data[acks[-1]]
                                if tcp_vers == "tahoe":
                                    message.receive_window = 1  # bring window all the way back to 1
                                    window = 1
                                elif tcp_vers == "reno":
                                    message.receive_window /= 2  # cut window in half
                                    window = message.receive_window
                                tcp_change = 1
                                #set new timeout value
                                pts.append(message.sequence_num)
                                new_est = (1 - .125) * self.SRTT + .125 * (end - start)
                                new_dev = (1 - .25) * self.RTTVAR + .25 * abs(self.SRTT - ((end - start) / 2))
                                self.SRTT = new_est

                                self.RTTVAR = new_dev
                                self.timeout = self.SRTT + 4 * self.RTTVAR
                                if self.timeout < 1:
                                    self.timeout = 1
                                break
                            else:
                                if message.receive_window <= ssthreshold:

                                    message.receive_window *= 2  # double window after 1 RTT if within ssthresh
                                    window = message.receive_window
                                else:
                                    ssthreshold /= 2  # cut ssthreshold in half once threshold reached
                                    message.receive_window += 1  # increment window by 1 after threshhold reached
                                    window = message.receive_window
                                break

                        else:
                            print("increase window")
                            if message.receive_window <= ssthreshold:

                                message.receive_window *= 2  # double window after 1 RTT if within ssthresh
                                window = message.receive_window
                            else:
                                ssthreshold /= 2  # cut ssthreshold in half once threshold reached
                                message.receive_window += 1  # increment window by 1 after threshhold reached
                                window = message.receive_window
                            break
                    
                        



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
                message = TCP_header(port, cur_seq, cur_ack, 0, 0, 1, 1, "")

                log.append([self.client_sock.getsockname()[1], port, "FIN", len(message.get_bits()), message.receive_window, time.time()])
                self.data_sent +=104
                self.client_sock.sendto(message.get_bits(), (address, port))

                data, addr = self.client_sock.recvfrom(1024)
                message = bits_to_header(data)

                if message.ACK == 1:
                    break

        elif putah == 1:
            message = TCP_header(port, cur_seq, cur_ack, 0, 1, 0, 1, "")

            log.append([self.client_sock.getsockname()[1], port, "ACK", len(message.get_bits()), message.receive_window, time.time()])
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
    receive_window = int(bits[104:120], 2)
    print("in bits to header 1")
    try:
        data_string = bits[120:]
        data = ""
        length = len(data_string) / 8

        for x in range(int(length)):
            start = x * 8
            end = (x + 1) * 8
            data += chr(int(str(data_string[start:end]), 2))
    except:
        data = ""
    return TCP_header(dst_port, seq_num, ack_num, syn, ack, fin, receive_window,data, src_port)

def writetofile(port):
    file_name = str(port) + "_berryessa.txt"
    with open(file_name, 'w') as f:
         for i in range(0, len(log)):
            f.write(str(log[i][0]) + " | " + str(log[i][1]) + " | "+ str(log[i][2])+ " | " + str(log[i][3]) + " | " + str(log[i][4]) + "|" + str(log[i][5]) + "\n")

def create_graph(tcp_version):
    y_points = np.array(window_sizes)

    plt.plot(y_points)
    plt.title(tcp_version + " Graph")
    plt.xlabel("Transmission Round")
    plt.ylabel("Congestion Window")

    plt.savefig(tcp_version + ".png")


if __name__ == '__main__':
    server_ip = sys.argv[2]
    port = int(sys.argv[4])
    tcp_vers = sys.argv[6]
    file = sys.argv[8]
    client = Client()

    handshake_message = client.handshake(server_ip, port)
    print("client connectione established")
    print(client.data_port)
    if client.connection == True and handshake_message != "":
        start = time.perf_counter()
        client.udpconnect(handshake_message, server_ip, client.data_port, file, tcp_vers)
        end = time.perf_counter()
        time_elapsed = end-start
        print("Time to send file (seconds)s:", time_elapsed)
        bandwidth = client.data_sent/time_elapsed
        print("Bandwidth achieved (bits/second):", bandwidth)
        percent = client.packet_losses*100 / client.packets_sent
        print("Packet loss percent:", percent)

    writetofile(client.data_port)
    create_graph(tcp_vers)
# handshake:

# client: s=0 a=0  server: s=0, a=1
# client: s=1, a=1
# client: s=1 a=1 server: s=1 a=5
# cleint: s=5 a=5 server: s=5 a=9
# client: s=9 a=9

#python3 sender_solano.py --ip 127.0.0.1 --dest_port 32007 --input alice29.txt