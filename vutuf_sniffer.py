#!/usr/bin/env python

from scapy.all import *
import pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

from sqlalchemy.orm import sessionmaker

from commondis import *

import vutuf_base
from vutuf_base import Server,Packet,PacketError,session

conf.iface="eth1"

def process_packet(pkt):
    global session
    try:
        packet = Packet(pkt)
    except PacketError:
        pass
    else:
        session.add(packet)
        session.commit()

sniff(filter="udp port 67", prn=process_packet)


                                                                                                                                
