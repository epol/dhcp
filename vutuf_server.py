import socket

from scapy.all import *

from sqlalchemy.orm import sessionmaker

import vutuf_base
from vutuf_base import session,Server,Packet,PacketError


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", 67))


while 1:
    data, addr = s.recvfrom(1600)
    p = BOOTP(data)
    try:
        packet = Packet(p)
    except PacketError:
        pass
    else:
        session.add(packet)
        session.commit()

s.close()

