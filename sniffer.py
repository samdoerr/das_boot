from ftp_cmds import cmd_list
from scapy.all import *
from collections import namedtuple

ftp_cmds = set(cmd_list)

ip_pair = namedtuple("ip_pair", ["src", "dst"])

ftp_packets = []
quick_lookup = {}

def store_packet(src, dst, parsed_data):
    combo = ip_pair(src, dst)
    if combo in quick_lookup:
        index = quick_lookup[combo]
        ftp_packets[index].append(parsed_data)
    else:
        quick_lookup[combo] = len(ftp_packets)
        ftp_packets.append([parsed_data])

def Raw_check(pkt):
    try:
        if pkt[Ether].type == 0x800 and pkt[IP].proto == 6:
            try:
                parsed_data = reduce_string(pkt[TCP].load)
                if parsed_data.split(" ", 1)[0] in ftp_cmds:
                    store_packet(pkt[IP].src, pkt[IP].dst, parsed_data)
            except AttributeError:
                pass
    except IndexError:
        pass

def reduce_string(string):
    ending = "\r\n"
    if string.endswith(ending):
            return string[:-len(ending)]
    else:
            return string

sniff(prn=lambda x: Raw_check(x))

print '\n'

for key, value in quick_lookup.items():
    print key.src + " >>> " + key.dst
    print "\n".join(ftp_packets[value]) + "\n"
