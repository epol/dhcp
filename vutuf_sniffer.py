#!/usr/bin/env python

from scapy.all import *
import pcap
conf.use_pcap=True
import scapy.arch.pcapdnet

from sqlalchemy.orm import sessionmaker

from commondis import *

import vutuf_base
from vutuf_base import Server,Packet

conf.iface="eth1"

Session = sessionmaker(bind=vutuf_base.engine)
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
                                                                                                                                
