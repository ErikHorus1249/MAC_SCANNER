from celery import shared_task
import socket
import scapy.all as scapy
from multiprocessing import Pool
import time
import ipaddress
import netifaces
import json
from socket import *
import socket
import urllib.request
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen


# Highlight text color  
host_color = '\033[32m'
normal_color = '\033[39m'
normalbg_color = '\033[49m'
header_color = '\033[33m'
error_color = '\033[31m'
blue_color = '\033[103m'

# Arp scanning use arp ping(method) in module scapy
@shared_task
def scan_arp(ip):
    target_ip = ip
    ssh_port,telnet_port, trojan_port = 22, 23, 3333 # set value for port
    try:
        ans,unans = scapy.arping(target_ip,verbose=0)
        for an in ans:
            return [an[1].sprintf("%ARP.psrc%"), an[1].sprintf("%Ether.src%"), \
                get_info(an[1].sprintf("%Ether.src%")), \
                scan_port(an[1].sprintf("%ARP.psrc%"), ssh_port), \
                scan_port(an[1].sprintf("%ARP.psrc%"), telnet_port), \
                scan_port(an[1].sprintf("%ARP.psrc%"), trojan_port)] \

    except Exception as e:
        print ("Error !".format(e))
        print(e)
        return 

# MAC vendor lookup
@shared_task
def get_info(mac):
    url = "http://macvendors.co/api/%s" % mac
    try:
        data = json.load(urllib.request.urlopen(url))
        return data['result']['company']
    except Exception as e:
        return 'Unknown'

# Ssh or telnet protocol port scanning 
@shared_task
def scan_port(ip, port):
   host = gethostbyname(ip)
   if get_connection(host,port) == 0 or get_connection(host,port) == 0:
      return True
   return False

# Enable port checking 
@shared_task
def get_connection(host,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(1)
      conn = s.connect_ex((host, port))
      return conn

# Get ip range ex:192.168.0.0/24
@shared_task
def get_ip(ip_range):
    for ip in ipaddress.IPv4Network(ip_range):
        print(ip)

@shared_task
def run():
    num_procs = 256 # the number of threads handled
    pool = Pool(processes=num_procs)
    ip_range = get_IpRange()
    print('by @erikhorus') 
    print(f'{blue_color}{error_color}\t\t\t\t\t IP range : {ip_range:8} Interface: {get_Default_Interface():4}{normalbg_color}')
    print (header_color + '-'*120)
    print ("\tIP\t\tMAC\t\t\tINFO\t\t\t\t\t\t\tSSH\tTELNET\tTROJAN")
    print ('-'*120 + normal_color)
    
    count = 1
    for res in pool.imap_unordered(scan_arp, [str(ip) for ip in ipaddress.IPv4Network(ip_range)]):
        if res != None :
            if res[3] == True or res[4] == True or res[5] == True:
                print(f'{error_color}{count:3} | {host_color}{res[0]:14} {res[1]:20} {res[2]:62} {str(res[3]):8} {str(res[4]):5} {str(res[5]):5}')
            else :
                print(f'{error_color}{count:3} | {normal_color}{res[0]:14} {res[1]:20} {res[2]:62} {str(res[3]):8} {str(res[4]):5} {str(res[5]):5}')
            count += 1
    

# Get ip range ex:192.168.0.0/24
@shared_task
def get_IpRange():
    INTER = get_Default_Interface()
    NETMASK = str(netifaces.ifaddresses(INTER)[netifaces.AF_INET][0]['netmask'])
    IP = str(netifaces.ifaddresses(INTER)[netifaces.AF_INET][0]['addr'])
    return str(ipaddress.ip_network(IP+'/'+NETMASK, strict=False))

# get network interface default
@shared_task
def get_Default_Interface():
    gws=netifaces.gateways()
    return gws['default'][netifaces.AF_INET][1]

@shared_task
def main():
    start_time = time.time()
    run()
    print(header_color + "\n--->  time execution %s s" % round(time.time() - start_time,2) +normal_color)

# test
main()