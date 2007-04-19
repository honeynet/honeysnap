"""
test_pcapre.py

Copyright (c) 2007 The Honeynet Project

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
"""

# $Id$

import unittest     
from socket import inet_aton
from nose.tools import raises 

import re
from honeysnap.importers.pcapRE import *
 
class GotAMatch(Exception):
    pass

class test_pcapre(unittest.TestCase):
    def setUp(self):
        pass              
     
    def test_init(self):
        """should be able to create a pcap object"""
        x = PcapRE('dummy pcap')
        assert x.pattern == None
        assert x.exp == None
        assert x.p == 'dummy pcap'
        
    def test_set_action(self):
        """set_action to should action to the given func"""
        x = PcapRE(None)
        x.set_action(len)
        assert x.action == len
        
    def test_set_re(self):
        """set_re should set regex to search on"""
        pattern = "testing, testing *"
        regex = re.compile(pattern)
        x = PcapRE(None)
        x.set_re(pattern)
        print regex
        print x.pattern
        assert x.exp == regex
        assert x.pattern == pattern

    @raises(PcapReError)
    def test_no_action(self):
        """should raise error if no action set"""
        x = PcapRE('dummy')
        x.start()

    @raises(GotAMatch)
    def test_match_tcp(self):
        """should match in a tcp packet"""
        def action(m, proto, shost, sport, dhost, dport, pay):
            raise GotAMatch
        pkt = dpkt.ethernet.Ethernet(src='000000', dst='000000', data=dpkt.ip.IP(src=inet_aton('1.2.3.4'), 
                                     dst=inet_aton('1.2.3.4'), p=17, data=dpkt.udp.UDP(sport=11, dport=12, data='bash1')))        
        x = PcapRE('dummpy')  
        x.set_re('b*1') 
        x.set_action(action)
        x.handle_ip(11111.0, pkt)
     
    @raises(GotAMatch)    
    def test_match_udp(self):
        """should match in a udp packet""" 
        def action(m, proto, shost, sport, dhost, dport, pay):
            raise GotAMatch
        pkt = dpkt.ethernet.Ethernet(src='000000', dst='000000', data=dpkt.ip.IP(src=inet_aton('1.2.3.4'), 
                                     dst=inet_aton('1.2.3.4'), p=17, data=dpkt.udp.UDP(sport=11, dport=12, data='bash')))        
        x = PcapRE('dummy')  
        x.set_re('ba*') 
        x.set_action(action)
        x.handle_ip(11111.0, pkt)

    def test_gen_cmpx(self):
        """gen_cmpx should generate a function"""
        assert(type(gen_cmpx([]))) == type(lambda x: x)
        
    def test_cmpx(self):
        """cmpx should compare in the right way"""
        cmpx = gen_cmpx( [6667])
        assert cmpx([34, 80], [56, 5555]) == 1
        assert cmpx([56, 5555], [34, 80]) == -1  
        assert cmpx([45, 4567], [45, 2222]) == 1
        assert cmpx([45, 2222], [45, 4567]) == -1
        assert cmpx([45, 80], [45, 4567]) == -1
        assert cmpx([45, 4567], [45, 80]) == 1
        assert cmpx([45, 80], [ 45, 6667]) == 1
        assert cmpx([45, 6667], [45, 80]) == -1  
        assert cmpx([23, 5556], [23, 5556]) == 0
      
    def test_pcap_re_counter(self):   
        """should be able to init a PcapReCounter"""
        p = PcapReCounter('dummy') 
        assert p.results == {}
        assert p.action == p.simple_counter    
        
    def test_simple_counter(self):
        """simple_counter should count"""
        p = PcapReCounter('dummy')
        proto = 6
        shost = '1.2.3.4'
        dhost = '2.3.4.5'
        sport = 66
        dport = 67
        key = (proto, shost, sport, dhost, dport) 
        for i in xrange(1, 5):
            p.simple_counter(None, proto, shost, sport, dhost, dport, 'testing')
            assert p.results[key] == i

    def test_server_ports(self):
        """
        server_ports should guess at which end of the connection is a server
        based on port numbers and flows
        """  
        p = PcapReCounter('dummy')
        p.results = { (6, '192.168.0.1', 889, '192.168.0.2', 6668) : 34,
                      (6, '192.168.0.2', 6668, '192.168.0.1', 889) : 34,
                    }
        assert p.server_ports() == [889]
        assert p.server_ports([6668]) == [6668]
        p.results = { (6, '192.168.0.1', 56783, '192.168.0.2', 25) : 45,
                      (6, '192.168.0.3', 45, '192.168.0.1', 25) : 1,
                      (6, '192.168.0.2', 25, '192.168.0.1', 56784) : 43,
                      (6, '192.168.0.5', 6667, '192.168.0.1', 4567) : 34,
                      (6, '192.168.0.1', 4567, '192.168.0.5', 6667) : 34,
        }
        assert p.server_ports() == [25, 4567]
        assert p.server_ports([6667]) == [25, 6667] 
        assert p.server_ports([23, 6667]) == [25, 6667]
        assert p.server_ports([25, 6667]) == [25, 6667]
    
if __name__ == '__main__':
    unittest.main()