#!/usr/bin/env python

from scapy.all import *
import pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

conf.iface="eth1"

good_servers = [ '192.168.251.2', '192.168.251.3', '192.168.200.1', '192.168.201.1', '192.168.80.3', '192.168.80.4', '192.168.31.1' ]
#good_servers = []
good_smac = [ 'f0:1c:2d:ef:cb:01', '00:30:48:94:71:12', '00:50:56:87:0f:99', '00:1b:17:00:02:30', '00:30:18:4b:98:06', '00:40:48:b2:8d:fc', '78:24:af:3a:6e:eb', '78:24:af:3a:71:f3', '00:01:c0:16:cd:19' ]
# core, gea, tea, firewal, wigo, wigo2, utopia, farpoint, versari

pkts = []

def convert_options(pkt):
    dic = { option[0] : option[1] for option in pkt[DHCP].options if type(option) is tuple }
    return dic

def get_dhcp_infos(pkt):
    if BOOTP not in pkt:
        return None
    data = {}
    data['srcmac']=pkt[Ether].src
    data['srcip']=pkt[IP].src
    data['giaddr']=pkt[BOOTP].giaddr
    data['server_id'] = 'None'
    data['vlan'] = 'None'
    data['yiaddr'] = pkt[BOOTP].yiaddr
    data['ciaddr'] = pkt[BOOTP].ciaddr
    data['bootpop'] = pkt[BOOTP].op
    if DHCP in pkt:
        options = convert_options(pkt)
        if 'server_id' in options:
            data['server_id']=options['server_id']
        if 'message-type' in options:
            data['message-type']=options['message-type']
    if Dot1Q in pkt:
        data['vlan'] = pkt[Dot1Q].vlan
    return data

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
                                                                                                                                
