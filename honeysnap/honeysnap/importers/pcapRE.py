################################################################################
# (c) 2006, The Honeynet Project
#   Author: Jed Haile  jed.haile@thelogangroup.biz
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

import re
import sys
import socket
import string
from operator import itemgetter 
import dpkt
import pcap

class PcapReError(Exception):
    pass

def gen_cmpx(server_port_list):
    """
    Generate a closure to sort an arroy of (count, port) values
    If a port appears in server_port_list, it is assumed to be lower in value than a non-member
    """ 
    def cmpx(x, y):   
        if cmp(x[0], y[0]):
            return cmp(y[0], x[0])
        else:
            if x[1] in server_port_list and not y[1] in server_port_list:
                return -1
            if y[1] in server_port_list and not x[1] in server_port_list:
                return 1
            return cmp(x[1], y[1])
    return cmpx

class PcapRE(object):
    """
    Takes a pcapObj as an argument.
    """
    def __init__(self, pcap):
        self.exp = None  
        self.pattern = None
        self.p = pcap    
        self.action = None
        
    def set_re(self, pattern):
        """
        Arg is a string that will be treated as a regular expression
        """
        self.exp = re.compile(pattern)
        self.pattern = pattern

    def set_action(self, action):
        self.action=action

    def start(self):
        """Iterate over a pcap object"""  
        if not self.action:
            raise PcapReError('Action not set (use setAction)')  
        for ts, buf in self.p:
            self.packet_handler(ts, buf)

    def packet_handler(self, ts, buf):   
        """Process a pcap packet buffer""" 
        try:
            pkt = dpkt.ethernet.Ethernet(buf)
        except dpkt.Error:
            return  
        self.handle_ip(ts, pkt)    
   
    def handle_ip(self, ts, pkt): 
        m = None
        pay = None  
        subpkt = pkt.data
        if type(subpkt) != type(dpkt.ip.IP()):  
            # skip non IP packets
            return          
        proto = subpkt.p
        shost = socket.inet_ntoa(subpkt.src)
        dhost = socket.inet_ntoa(subpkt.dst)
        try:
            if proto == socket.IPPROTO_TCP:
                tcp = subpkt.data
                pay = tcp.data
                dport = tcp.dport 
                sport = tcp.sport
            if proto == socket.IPPROTO_UDP: 
                udp = subpkt.data
                pay = udp.data
                dport = udp.dport
                sport = udp.sport
        except dpkt.Error:
            return  
        if pay is not None:
            m = self.exp.search(pay)
            if m:                
                self.action(m, proto, shost, sport, dhost, dport, pay)
     
class PcapReCounter(PcapRE):
    """Extension of PcapRE to do simple counting of matching packets"""
    def __init__(self, pcap):
        super(PcapReCounter, self).__init__(pcap)
        self.results = {}          
        self.action = self.simple_counter

    def simple_counter(self, m, proto, shost, sport, dhost, dport, pay):
        """Simple action that just counts matches"""  
        key = (proto, shost, sport, dhost, dport) 
        if key not in self.results:
            self.results[key] = 0
        self.results[key] += 1
    
    def server_ports(self, server_port_list=[]): 
        """
        Takes as input the results from a pcapRECount object, and works out which ports are the server ports
        If we have two ports with equal counts, assume the lower numbered is the server unless one of the ports
        is in server_port_list
        """   
        ports = {}
        for key, val in self.results.items():  
            proto=key[0]
            source=key[1]
            sport=key[2]
            dest=key[3]
            dport=key[4]
            count=val
            if proto == socket.IPPROTO_TCP:
                if ports.has_key(sport):
                    ports[sport].add(dport)
                else:
                    ports[sport] = set([dport])
                if ports.has_key(dport):
                    ports[dport].add(sport)
                else:
                    ports[dport] = set([sport])
        portcount = []
        for i in ports.keys():
            portcount.append( (len(ports[i]), i) )
        res = {}                    
        seen = {}      
        for port in [ i[1] for i in sorted(portcount, cmp=gen_cmpx(server_port_list) )]:
            if seen.has_key(port):
                continue
            if res.has_key(port):
                res[port].add(port)
            else:
                res[port] = ports[port]
            for subport in ports[port]:
                seen[subport] = True  
        return res.keys() 
    