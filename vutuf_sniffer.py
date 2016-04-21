#!/usr/bin/env python

from scapy.all import *
import pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

from commondis import *

conf.iface="eth1"

Session = sessionmakeer(bind=vutuf_base.engine)
session = Session()

def process_packet(pkt):
    global session
    try:
        packet = Packet(pkt)
    except:
        pass
    else:
        session.add(packet)
        session.commit()

sniff(filter="udp port 67", prn=process_packet)

session.close()
s.close()
                                                                                                                                
