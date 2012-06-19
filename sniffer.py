import os, sys
import ftp_cmds

from scapy.all import *

#Authentification
#euid = os.geteuid()
#if euid != 0:
#    print "Script not started as Root. Running sudo..."
#    args = ['sudo', sys.executable] + sys.argv + [os.environ]
#    os.execlpe('sudo',  *args)

filter_ip = "host 172.16.21.216"
ether_type = 0x800 #IP
ip_protocol = 6 #TCP

count = 1;
ftp_cmds = set(ftp_cmds.cmd_list)

def incr_count():
    global count
    count += 1

def Raw_check(x):
    if x[Ether].type == ether_type and x[IP].proto == ip_protocol:
        if x.getlayer(Raw) != None and x[IP].src == filter_ip[5:]:
            parsed_data = reduce_string(x[TCP].load)
            if len(parsed_data) > 0:
                print str(count) + " Raw Data: " + parsed_data
                incr_count()

def reduce_string(string):
    ending = "\n"
    if string.endswith(ending):
            return string[:-len(ending)]
    else:
            return string

sniff(filter = filter_ip, prn=lambda x: Raw_check(x))
