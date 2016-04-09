#!/usr/bin/env python2.7

from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

netopt = {'client_listen_port':"68",
          'server_listen_port':"67",
          'listen_address':"0.0.0.0"}

goodservers_str = [ '192.168.251.2', '192.168.251.3' ]
goodservers = [ [ int(n) for n in s.split('.') ] for s in goodservers_str ] 

class Server(DhcpServer):
    def __init__(self, options):
        DhcpServer.__init__(self,options["listen_address"],
                            options["client_listen_port"],
                            options["server_listen_port"])
        
    def HandleDhcpDiscover(self, packet):
        pass

    def HandleDhcpRequest(self, packet):
        server_identifier = packet.GetOption('server_identifier')
        if server_identifier is not None:
            if server_identifier is not []:
                if server_identifier not in goodservers:
                    with open('badpackets.txt','a') as f:
                        f.writeline(packet.str())
                    print packet.str()

    def HandleDhcpDecline(self, packet):
        pass

    def HandleDhcpRelease(self, packet):
        pass

    def HandleDhcpInform(self, packet):
        pass


def main():
    server = Server(netopt)
    
    while True :
        server.GetNextDhcpPacket()



if __name__ == "__main__":
    main()
