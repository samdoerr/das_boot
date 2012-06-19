import os, sys
import ftp_cmds

from scapy.all import *

#Authentification
#euid = os.geteuid()
#if euid != 0:
#    print "Script not started as Root. Running sudo..."
#    args = ['sudo', sys.executable] + sys.argv + [os.environ]
#    os.execlpe('sudo',  *args)

count = 1;
ftp_cmds = set(ftp_cmds.cmd_list)

def incr_count():
    global count
    count += 1

def Raw_check(x):
    try:
        if x[Ether].type == 0x800 and x[IP].proto == 6:
            try:
                parsed_data = reduce_string(x[TCP].load)
                if parsed_data.split(" ", 1)[0] in ftp_cmds:
                    print str(count) + " Raw Data: " + parsed_data
                    incr_count()
            except AttributeError:
                pass
    except IndexError:
        pass

def reduce_string(string):
    ending = "\n"
    if string.endswith(ending):
            return string[:-len(ending)]
    else:
            return string

sniff(prn=lambda x: Raw_check(x))
