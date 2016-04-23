import socket

from scapy.all import *

from sqlalchemy.orm import sessionmaker

import vutuf_base
from vutuf_base import Server,Packet


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", 67))

Session = sessionmaker(bind=vutuf_base.engine)
session = Session()

while 1:
    data, addr = s.recvfrom(1600)
    p = BOOTP(data)
    try:
        packet = Packet(p)
    except:
        pass
    else:
        session.add(packet)
        session.commit()

session.close()
s.close()

