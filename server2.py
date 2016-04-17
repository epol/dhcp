import socket

from scapy.all import *

import commondis

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", 67))

good_servers = ['192.168.251.2']

while 1:
    data, addr = s.recvfrom(1600)
    p = BOOTP(data)
    data = commondis.get_dhcp_infos(p)
    if data['message-type'] == 3: #DHCPREQUEST
        if data['server_id'] is not None and data['server_id'] not in good_servers:
            print("From gateway {giaddr} request for the address {requested_addr} and server_id {server_id}\n".format(**data))

s.close()
