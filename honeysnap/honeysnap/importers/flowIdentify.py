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

import pcap
import socket
import sys
import time                        
from datetime import datetime  

import dpkt                                                        

from honeysnap.util import make_dir  
from honeysnap.singletonmixin import HoneysnapSingleton      
from honeysnap.model.model import *
                 
# regard a flow as new if we don't see a packet for FLOW_DELTA seconds         
FLOW_DELTA = 3600         
         
class DecodeError(Exception):
    pass
             
class DuplicateFlow(Exception):
    pass

class FlowIdentify(object):
    """
    FlowIdentify takes a pcapObj
    This class reads the pcap data, hands it to a decoder, and then keys each packet
    by (srcip, dstip, dport), before storing in a db
    """
    def __init__(self, file, filename, hp): 
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.engine = connect_to_db(options['dburi'], options['debug'])
        self.filename = filename
        self.p = pcap.pcap(file)
        self.session = create_session()
        self.fq = self.session.query(Flow)  
        self.ipq = self.session.query(Ip)
        self.hp = Honeypot.get_or_create(self.session, hp) 
        self.flows = {}

    def setFilter(self, filter): 
        """Set pcap filter on file"""
        self.p.setfilter(filter)
        
    def start(self):
        """Iterate over a pcap object"""
        for ts, buf in self.p:
            self.packet_handler(ts, buf)
        self.hp.save_flow_changes(self.session)

    def packet_handler(self, ts, buf):
        """Process a pcap packet buffer"""   
        try:
            (src, dst, sport, dport, proto, length) = self.decode_packet(buf)
        except (dpkt.Error, DecodeError):
            return   
        try:
            self.match_flow(ts, src, dst, sport, dport, proto, length)           
        except DuplicateFlow:
            return

    def match_flow(self, ts, src, dst, sport, dport, proto, length ):
        # have we seen matching flow in this pcap file/already? 
        time = datetime.utcfromtimestamp(ts)
        cached_flows = self.flows.get( (src, dst, sport, dport, proto), None)
        if cached_flows:
            for flow in cached_flows:      
                if flow.lastseen > datetime.utcfromtimestamp(ts-FLOW_DELTA):  
                    flow.lastseen = datetime.utcfromtimestamp(ts)
                    flow.bytes += length;
                    flow.packets += 1;
                    return
        srcid = Ip.id_by_ip(src)
        dstid = Ip.id_by_ip(dst)        
        flows = self.fq.select(and_(Flow.c.src_id == srcid, Flow.c.dst_id == dstid, Flow.c.sport == sport, 
            Flow.c.dport == dport, Flow.c.lastseen > datetime.utcfromtimestamp(ts-FLOW_DELTA)), order_by = desc(Flow.c.starttime))
        if flows:              
            flow = flows[0]    # if more than one, append data to the last seen flow
            if flow.starttime == time:
                raise DuplicateFlow
            else:     
                flow.bytes += length; 
                flow.packets += 1     
                flow.lastseen = datetime.utcfromtimestamp(ts)
                if not cached_flows:
                    self.flows[(src, dst, sport, dport, proto)] = []
                self.flows[(src, dst, sport, dport, proto)].append(flow)
        else:                   
            flow = Flow(ip_proto=proto, src_id=srcid, dst_id=dstid, sport=sport, dport=dport, 
                        starttime=time, lastseen=time, packets=1, bytes=length, filename=self.filename)
            self.hp.flows.append(flow)                   
            if not cached_flows:
                self.flows[(src, dst, sport, dport, proto)] = []
            self.flows[(src, dst, sport, dport, proto)].append(flow)

    def decode_packet(self, buf):
        """extract basic info (src, dst, sport, dport, length) from a packet and return the data"""
        pkt = dpkt.ethernet.Ethernet(buf)
        subpkt = pkt.data
        if type(subpkt) != type(dpkt.ip.IP()):
            # skip non IP packets
            raise DecodeError('Not an IP packet')
        proto = subpkt.p
        src = socket.inet_ntoa(subpkt.src)
        dst = socket.inet_ntoa(subpkt.dst)
        if proto == socket.IPPROTO_TCP or proto == socket.IPPROTO_UDP:  
            sport = subpkt.data.sport
            dport = subpkt.data.dport    
            length = len(subpkt.data.data)
        elif proto == socket.IPPROTO_ICMP:
            icmp = subpkt.data
            # not sure about this, but it'll do for now               
            sport = icmp.type
            dport = icmp.code        
            length = len(icmp.data)  
        else:               
            # other wacky IP proto                   
            sport = -1
            dport = -1
            length = len(subpkt.data) 
        return (src, dst, sport, dport, proto, length)            


