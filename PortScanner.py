from socket import *
import socket


def scan_port(ip):
    PORT = 3333
    HOST = gethostbyname(ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    # returns an error indicator
    result = s.connect_ex((HOST,PORT))
    if result ==0:
        # print("Port {} is open".format(PORT))
        return True
    else:
        return False
    s.close()

# print(scan_port('192.168.0.111'))
