#!/usr/bin/env python

import scapy.all

def convert_options(pkt):
    dic = { option[0] : option[1] for option in pkt[scapy.all.DHCP].options if type(option) is tuple }
    return dic

def get_dhcp_infos(pkt):
    if scapy.all.BOOTP not in pkt:
        return None
    data = {}
    data['srcmac']=pkt[scapy.all.Ether].src
    data['srcip']=pkt[scapy.all.IP].src
    data['giaddr']=pkt[scapy.all.BOOTP].giaddr
    data['server_id'] = 'None'
    data['message-type']= 'None'
    data['vlan'] = 'None'
    data['yiaddr'] = pkt[scapy.all.BOOTP].yiaddr
    data['ciaddr'] = pkt[scapy.all.BOOTP].ciaddr
    data['bootpop'] = pkt[scapy.all.BOOTP].op
    if scapy.all.DHCP in pkt:
        options = convert_options(pkt)
        if 'server_id' in options:
            data['server_id']=options['server_id']
        if 'message-type' in options:
            data['message-type']=options['message-type']
    if scapy.all.Dot1Q in pkt:
        data['vlan'] = pkt[scapy.all.Dot1Q].vlan
    return data
