#!/usr/bin/env python
# encoding: utf-8
################################################################################
#   (c) 2007 The Honeynet Project
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
################################################################################

# $Id$

import unittest       
from datetime import datetime
from nose.tools import raises
from time import time, gmtime, asctime
from honeysnap.model.model import *
from honeysnap.importers.flowIdentify import *

class test_flowIdentify(unittest.TestCase):
    def setUp(self):      
        self.engine = connect_to_db('sqlite:///') 
        # this is very nasty....           
        # don't want to run __init__ as don't have options or a file      
        self.session = create_session()        
        FlowIdentify.__init__ = lambda self: None 
        self.hp = Honeypot.get_or_create(self.session, '192.168.0.1')
        self.fid = FlowIdentify()   
        self.fid.filename = 'testing'
        self.fid.new_flows = {}
        self.fid.updated_flows = {}
        self.fid.count = 0 
        self.fid.hpid =self.hp.id

    def tearDown(self):
        Ip.id_cache = {}
        self.session.clear()   
        metadata.drop_all()
                                  
    @raises(DecodeError) 
    def test_decode_packet_nonip(self):    
        """decode_packet should raise DecodeError for non-IP packet"""
        buf = '\x00\x01\x08\x00\x06\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.fid.decode_packet(buf)

    def test_decode_packet_tcp(self):
        """decode_packet should get values right for tcp packet"""
        buf = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00K\x00\x00\x00\x00@\x06\xf9Y\xc0\xa8\x00\x01\xc0\xa8\x00\x02\x1a\x0b\xd1\x0c\x04\xc45].c^`P\x18\x0bh\xcd\xc5\x00\x00PING :Lelystad.NL.EU.UnderNet.Org\r\n'
        (src, dst, sport, dport, proto, length) = self.fid.decode_packet(buf)
        print src, dst, sport, dport, proto, length
        assert proto == socket.IPPROTO_TCP
        assert src == '192.168.0.1'
        assert dst == '192.168.0.2'
        assert sport == 6667
        assert dport == 53516  
        assert length == 35
        
    def test_decode_packet_udp(self):
        """decode_packet should get values right for udp""" 
        buf = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00I\xae\xf7\x00\x00\xff\x11\xf8\xa9\n\x00\x00\x01\n\x00\x00\x02\xc3\xe7\x005\x00\x08\xe6\xf3hello world'
        (src, dst, sport, dport, proto, length) = self.fid.decode_packet(buf)
        print src, dst, sport, dport, proto, length 
        assert proto == socket.IPPROTO_UDP
        assert src == '10.0.0.1'
        assert dst == '10.0.0.2'
        assert sport == 50151
        assert dport == 53
        assert length == 11
        
    def test_decode_packet_icmp(self):
        """decode_packet should get values right for icmp"""
        buf = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00L\x00\x00@\x00@\x01&\xaf\n\x00\x00\x01\n\x00\x00\x02\t\x03\xf6\xfc'
        (src, dst, sport, dport, proto, length) = self.fid.decode_packet(buf)
        print src, dst, sport, dport, proto, length 
        assert proto == socket.IPPROTO_ICMP
        assert src == '10.0.0.1'
        assert dst == '10.0.0.2'
        assert sport == 9
        assert dport == 3
        assert length == 4

    def test_decode_packet_other(self):
        """decode_packet should set sport and dport = -1 for other protos"""
        buf = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00L\x00\x00@\x00@p&\xaf\n\x00\x00\x01\n\x00\x00\x02\x01\x17d\x02\x00\x00\x00d'
        (src, dst, sport, dport, proto, length) = self.fid.decode_packet(buf)
        print src, dst, sport, dport, proto, length 
        assert proto == 112  # vrrp 
        assert src == '10.0.0.1'
        assert dst == '10.0.0.2'
        assert sport == -1
        assert dport == -1
        assert length == 16        

    def test_sub_second_ts(self):
        """should store sub-second time stamps correctly"""  
        ts = 11111.23456
        f = Flow( ip_proto=6, src_id=1, dst_id=1, sport=80, 
                  dport=664, starttime=ts, lastseen=ts, packets=1, 
                  bytes=20, filename='testing') 
        self.hp.flows.append(f) 
        self.session.flush()
        id = f.id
        del f
        f = self.session.query(Flow).selectone(Flow.c.id==id)
        assert f.starttime == datetime.fromtimestamp(ts)

    def test_match_flow_in_cache(self):
        """match_flow should spot if flow has been seen already this file"""  
        ts = 111111.0 
        self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ] = \
                                                    [dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=1, dst_id=2, sport=80, 
                                                    dport=664, starttime=datetime.fromtimestamp(ts), 
                                                    lastseen=datetime.fromtimestamp(ts), packets=1, 
                                                    bytes=20, filename='testing')]
        self.fid.match_flow(ts, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)                                                    
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 32  
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['lastseen'] == datetime.fromtimestamp(ts)

    def test_match_flow_over_boundary_in_cache(self):
        """match_flow should spot if flow has been seen already this file, three packet case"""  
        ts1 = 111111.0  
        ts2 = ts1 + FLOW_DELTA -3
        ts3 = ts1 + FLOW_DELTA + 10
        self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ] = \
                                                    [dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=1, dst_id=2, sport=80, 
                                                    dport=664, starttime=datetime.fromtimestamp(ts1), 
                                                    lastseen=datetime.fromtimestamp(ts1), packets=1, 
                                                    bytes=20, filename='testing')]
        self.fid.match_flow(ts2, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)                                                    
        self.fid.match_flow(ts3, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)        
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 44  
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['lastseen'] == datetime.fromtimestamp(ts3)


    def test_match_flow_in_cache_pre_hour(self):
        """match_flow should spot if flow has been seen already this file, but create new if it was more than FLOW_DELTA ago"""
        ts1 = 111111.0
        ts2 = ts1+FLOW_DELTA+3600
        self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ] = \
                                                    [dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=1, dst_id=2, sport=80, 
                                                    dport=664, starttime=datetime.fromtimestamp(ts1), 
                                                    lastseen=datetime.fromtimestamp(ts1), packets=1, 
                                                    bytes=20, filename='testing')]
        self.fid.match_flow(ts2, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)                                                    
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 20
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][1]['bytes'] == 12  

    def test_match_flow_in_db(self):
        """match_flow should spot flow in db and set cache correctly"""             
        src_id = Ip.id_get_or_create('192.168.0.1')
        dst_id = Ip.id_get_or_create('192.168.0.2')  
        ts = 111111.0                
        ts_dt = datetime.fromtimestamp(ts)
        flow_table.insert().execute(dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=src_id, dst_id=dst_id, sport=80, 
                                                    dport=664, starttime=ts_dt, lastseen=ts_dt, packets=1, 
                                                    bytes=20, filename='testing')) 
        self.fid.match_flow(ts+20, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)   
        print self.fid.updated_flows
        assert self.fid.updated_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 32
        assert self.fid.updated_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['lastseen'] == datetime.fromtimestamp(ts+20)
                                                                                                                               
    def test_match_flow_over_boundary_in_db(self):
        """match_flow should spot flow in db and set cache correctly"""             
        src_id = Ip.id_get_or_create('192.168.0.1')
        dst_id = Ip.id_get_or_create('192.168.0.2')  
        ts1 = 111111.0  
        ts2 = ts1 + FLOW_DELTA - 3
        ts3 = ts1 + FLOW_DELTA + 10
        flow_table.insert().execute( dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=src_id, dst_id=dst_id, sport=80, 
                                                    dport=664, starttime=datetime.fromtimestamp(ts1), 
                                                    lastseen=datetime.fromtimestamp(ts1), packets=1, 
                                                    bytes=20, filename='testing')) 
        self.fid.match_flow(ts2, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)
        self.fid.match_flow(ts3, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)
        assert self.fid.updated_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 44
        assert self.fid.updated_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['lastseen'] == datetime.fromtimestamp(ts3)

    def test_match_flow_in_db_pre_hour(self):
        """match_flow should spot flow in db, but create new if it was more than FLOW_DELTA ago"""             
        src_id = Ip.id_get_or_create('192.168.0.1')
        dst_id = Ip.id_get_or_create('192.168.0.2') 
        ts1 = 111111.0
        ts2 = ts1+FLOW_DELTA+564
        flow_table.insert().execute(dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=src_id, dst_id=dst_id, sport=80, 
                                                    dport=664, starttime=ts1, lastseen=ts1, packets=1, 
                                                    bytes=20, filename='testing'))       
        self.fid.match_flow(ts2, '192.168.0.1', '192.168.0.2', 80, 664, 6, 12)                                                    
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 12     

    def test_match_flow_new(self):
        """match_flow should create new flow if no flow matches"""    
        ts1 = 111111.0
        ts2 = ts1+3
        src_id = Ip.id_get_or_create('192.168.0.1')
        dst_id = Ip.id_get_or_create('192.168.0.2')      
        flow = dict(honeypot_id=self.fid.hpid, ip_proto=6, src_id=src_id, dst_id=dst_id, sport=80, 
                    dport=664, starttime=datetime.fromtimestamp(ts1), 
                    lastseen=datetime.fromtimestamp(ts1), packets=1, 
                    bytes=20, filename='testing')
        flow_table.insert().execute(flow)
        self.fid.updated_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ] = \
                    [flow]
        self.fid.match_flow(ts2, '192.168.0.1', '192.168.0.3', 80, 664, 6, 12)                                                             
        assert self.fid.updated_flows[ ('192.168.0.1', '192.168.0.2', 80, 664, 6) ][0]['bytes'] == 20        
        assert self.fid.new_flows[ ('192.168.0.1', '192.168.0.3', 80, 664, 6) ][0]['bytes'] == 12 

if __name__ == '__main__':
    unittest.main()