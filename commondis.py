#!/usr/bin/env python

import scapy.all

def convert_options(pkt):
    dic = { option[0] : option[1] for option in pkt[scapy.all.DHCP].options if type(option) is tuple }
    return dic

def get_dhcp_infos(pkt):
    if scapy.all.BOOTP not in pkt:
        return None
    data = {}
    if scapy.all.Ether in pkt:
        data['srcmac']=pkt[scapy.all.Ether].src
    else:
        data['srcmac']=None
    if scapy.all.IP in pkt:
        data['srcip']=pkt[scapy.all.IP].src
    else:
        data['srcip']=None
    data['giaddr']=pkt[scapy.all.BOOTP].giaddr
    data['server_id'] = None
    data['message-type']= None
    data['vlan'] = None
    data['yiaddr'] = pkt[scapy.all.BOOTP].yiaddr
    data['ciaddr'] = pkt[scapy.all.BOOTP].ciaddr
    data['chaddr'] = pkt[scapy.all.BOOTP].chaddr[:pkt[scapy.all.BOOTP].hlen].encode('hex')
    data['bootpop'] = pkt[scapy.all.BOOTP].op
    data['requested_addr'] = None
    if scapy.all.DHCP in pkt:
        options = convert_options(pkt)
        if 'server_id' in options:
            data['server_id']=options['server_id']
        if 'message-type' in options:
            data['message-type']=options['message-type']
        if 'requested_addr' in options:
            data['requested_addr'] = options['requested_addr']
    if scapy.all.Dot1Q in pkt:
        data['vlan'] = pkt[scapy.all.Dot1Q].vlan
    return data
