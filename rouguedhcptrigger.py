#!/usr/bin/env python

import random

from scapy.all import *
import pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

conf.iface="eth1"
conf.checkIPaddr = False

fam,hw = get_if_raw_hwaddr(conf.iface)

for i in [ 20,253,8]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff",src=hw)/Dot1Q(vlan=i)/IP(src="0.0.0.0",dst="255.255.255.255",ttl=1)/UDP(sport=68,dport=67)/BOOTP(chaddr=hw,xid=random.randint(0, 0xFFFFFFFF))/DHCP(options=[("message-type","discover"),"end"])
    sendp(pkt)
