from pickle import FALSE, TRUE
from client_putah import TCP_header
import sys
import threading
import socket
import binascii
class TCP_over_UDP(server_ip):
    def __init__(self):
        self.connections = [] #queue
        self.welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.welcome_socket.bind(("127.0.01", 53))
        self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_socket.bind(("127.0.01", 1985))
        #self.lock = threading.Lock()
    def thread_handshake(self):
        t = threading.Thread(target=self.handshake())
        t.daemon = True
        t.start()
    def handshake(self):
        start = 0
        packet, address = self.welcome_socket.recvfrom(32) #check this size
        if packet.get_type() == "SYN" and start == 0:
            synack = TCP_header()
            synack.custom_message(1,1,0)
            send(client_ip, 8888, synack)
            start+=1
        packet2, address = self.welcome_socket.recvfrom(32)
        if packet2.get_type() == "ACK" and start == 1:
            return 1
        else:
            print("Couldn't establish handshake...")
            return 0


    def send(self):
        pass
    def receive_data(self):
        pass

if __name__ == '__main__':
    client_ip = sys.argv[2]
    port = sys.argv[4]