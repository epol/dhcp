#!/usr/bin/env python

from scapy.all import *
import pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

from commondis import *

conf.iface="eth1"

good_servers = [ '192.168.251.2', '192.168.251.3', '192.168.200.1', '192.168.201.1', '192.168.80.3', '192.168.80.4', '192.168.31.1' ]
#good_servers = []
good_smac = [ 'f0:1c:2d:ef:cb:01', '00:30:48:94:71:12', '00:50:56:87:0f:99', '00:1b:17:00:02:30', '00:30:18:4b:98:06', '00:40:48:b2:8d:fc', '78:24:af:3a:6e:eb', '78:24:af:3a:71:f3', '00:01:c0:16:cd:19' ]
# core, gea, tea, firewal, wigo, wigo2, utopia, farpoint, versari

pkts = []

def format_data(data):
    if data is not None:
        return "Source MAC: {srcmac}, Source IP: {srcip}, Gateway Address: {giaddr}, Server ID: {server_id}, VLAN: {vlan}".format(**data)
    else:
        return None

def print_data(data):
    print format_data(data)

def is_bad_data(data):
    if data is not None:
        if data['message-type'] == 2: #DHCPOFFER
            if data['server_id'] not in good_servers or data['srcmac'] not in good_smac:
                return True
        elif data['message-type'] == 3: #DHCPREQUEST
            if data['server_id'] not in good_servers:
                return True
    return False

def process_packet(pkt):
    data = get_dhcp_infos(pkt)
    if is_bad_data(data):
        global pkts
        pkts.append(pkt)
        wrpcap("bad.cap",pkts)
        if data['message-type'] == 2:  #DHCPOFFER
            return format_data(data)
            
#sniff(filter="udp port 67", prn=print_bad_dhcp_reply)
#sniff(filter="udp port 67", prn=print_dhcp_reply)
sniff(filter="udp port 67", prn=process_packet)
                                                                                                                                
