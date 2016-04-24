#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module provides database definitions and basic operations on his objects

"""

# vutuf_base.py
# This file is part of VUTUF
# 
# Copyright (C) 2016 - Enrico Polesel
# 
# VUTUF is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# any later version.
# 
# VUTUF is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with VUTUF. If not, see <http://www.gnu.org/licenses/>.


import os
import sys
import datetime
import sqlalchemy
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.types import Boolean, Enum, DateTime, LargeBinary,Interval
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship,sessionmaker,backref,scoped_session
from sqlalchemy import create_engine


import commondis

engine = create_engine('sqlite:///vutuf.db')
session = scoped_session(sessionmaker(bind=engine))

Base = declarative_base()
 
class Server(Base):
    __tablename__ = 'server'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    ip = Column(String(16), nullable=False)
    good = Column(Boolean)
    
    def __init__(self, name, ip, good=False):
        self.name = name
        self.ip = ip
        self.good = good
    
    def __repr__(self):
        return "<Server({name},{ip},good={good})>".format(name=self.name,ip=self.ip,good=self.good)
 
    def last_seen(self):
        global session
        return session.query(Packet).filter(Packet.server==self).order_by(Packet.date.desc()).first().date

class Packet(Base):
    __tablename__ = 'packet'
    id = Column(Integer, primary_key=True)
    type = Column(Enum('offer','request'),nullable=False)
    raw = Column(LargeBinary(256), nullable=True)
    server_id = Column(Integer, ForeignKey('server.id'))
    server = relationship(Server, backref = backref('packets', order_by=id,cascade='all, delete-orphan'))
    srcmac = Column(String(20), nullable=True)
    chaddr = Column(String(20), nullable=True)
    vlan = Column(Integer, nullable = True)
    gateway = Column(String(20), nullable = True)
    address = Column(String(20), nullable=True)
    date = Column(DateTime, nullable=False)
    
    def __init__ (self,pkt):
        data = commondis.get_dhcp_infos(pkt)
        if data is None:
            raise PacketError("Not BOOTP packet")
        if data['server_id'] is None:
            raise PacketError("Not interesting")
        if data['bootpop'] == 1:  #BOOTREQUEST
            if data['message-type'] == 3:  #DHCPREQUEST
                self.type = 'request'
                self.address = data['requested_addr']
            else:
                raise PacketError("Not interesting")
        elif data['bootpop'] == 2:  #BOOTREPLY
            if data['message-type'] == 2:  #DHCPOFFER
                self.type = 'offer'
                self.address = data['yiaddr']
            else:
                raise PacketError("Not interesting")
        else:
            raise PacketError("Unknow bootp code")
        self.gateway = data['giaddr']
        self.srcmac = data['srcmac']
        self.chaddr = data['chaddr']
        self.vlan = data['vlan']
        self.date = datetime.datetime.now()

        global config
        if config.save_raw:
            self.raw = str(pkt)
        else:
            self.raw = None
        
        global session
        servercount = session.query(Server).filter(Server.ip==data['server_id']).count()
        if servercount > 1:
            raise PacketError("Too many servers with the same IP")
        elif servercount == 1:
            server = session.query(Server).filter(Server.ip==data['server_id']).one()
        else:
            server = Server(data['server_id'],data['server_id'],False)
            session.add(server)
            session.commit()
        self.server = server

    def __repr__(self):
        return "<Packet(server={server_name},address={address})>".format(server_name=self.server.name,address=self.address)

    def is_good(self):
        return self.server.good

class PacketError(Exception):
    def __init__(self,reason):
        self.reason = reason
    def __str__(self):
        return repr(self.reason)


class Config(Base):
    __tablename__ = 'config'
    id = Column(Integer, primary_key=True)
    save_raw = Column(Boolean, nullable=False)
    goodpacket_ttl = Column(Interval,nullable=False)
    badpacket_ttl = Column(Interval,nullable=False)
    
    def __init__(self, save_raw=True, goodpacket_ttl=datetime.timedelta(days=1), badpacket_ttl=datetime.timedelta(days=30)):
        self.save_raw=save_raw
        self.goodpacket_ttl = goodpacket_ttl
        self.badpacket_ttl = badpacket_ttl
        
    def __repr__(self):
        return "<Config(id={id},save_raw={save_raw},goodpacket_ttl={goodpacket_ttl},badpacket_ttl={badpacket_ttl})>".format(id=self.id,save_raw=self.save_raw,goodpacket_ttl=self.goodpacket_ttl,badpacket_ttl=self.badpacket_ttl)

Base.metadata.create_all(engine)

class ConfigError(Exception):
    def __init__(self,reason):
        self.reason = reason
    def __str__(self):
        return repr(self.reason)

    
def get_config(id=None):
    global session
    if id is None:
        query = session.query(Config)
        if query.count() ==0:
            config = Config()
            session.add(config)
            session.commit()
            return config
        elif query.count() ==1:
            return query.one()
        else:
            raise ConfigError("More than one configuration present, please specify an id")
    else:
        return session.query(Config).filter(Config.id==id).one()

def get_recent_bad_servers(delta=datetime.timedelta(days=1)):
    global session
    return session.query(Server).filter(Server.good==False).join(Server.packets).filter(Packet.date>delta).order_by(Packet.date.desc()).all()

def clean_packets():
    global config
    global session
    for p in session.query(Packet).filter(Packet.date<datetime.datetime.now()-config.goodpacket_ttl).join(Packet.server).filter(Server.good==True).all():
        session.delete(p)
    for p in session.query(Packet).filter(Packet.date<datetime.datetime.now()-config.badpacket_ttl).join(Packet.server).filter(Server.good==False).all():
        session.delete(p)
    session.commit()




try:
    config = get_config()
except:
    config = None

