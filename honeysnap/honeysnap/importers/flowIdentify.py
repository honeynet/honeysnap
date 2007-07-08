################################################################################
# (c) 2006, The Honeynet Project
#   Author: Arthur Clune arthur@honeynet.org.uk
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
from time import time, asctime

import dpkt 
import sqlalchemy                                                       

from honeysnap.singletonmixin import HoneysnapSingleton      
from honeysnap.model.model import *
                 
# regard a flow as new if we don't see a packet for FLOW_DELTA seconds         
FLOW_DELTA = 3600          

# write to db every N flows
LOAD_QUANTA = 20000
       
class DecodeError(Exception):
    pass
             
class DuplicateFlow(Exception):
    pass

class FlowIdentify(object):
    """
    FlowIdentify takes a pcapObj
    This class reads the pcap data, hands it to a decoder, and then keys each packet
    by (srcip, dstip, sport, dport, proto), before storing in a db
    """
    def __init__(self, file, filename, hp):  
        """Create object, open pcap file, set filter and create queries"""
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.engine = connect_to_db(options['dburi'], options['debug'])
        self.filename = filename
        self.session = create_session() 
        self.hp = hp
        self.hpid = Honeypot.get_or_create(self.session, hp).id
        self._init_pcap(file)
        self.new_flows = {}    
        self.updated_flows = {}
        self.count = 0        
        self.fq = flow_table.select(and_(
                    flow_table.c.lastseen > bindparam('timedelta'),
                    flow_table.c.src_id == bindparam('srcid'), 
                    flow_table.c.dst_id == bindparam('dstid'), 
                    flow_table.c.sport == bindparam('sport'), 
                    flow_table.c.dport == bindparam('dport'), 
                    flow_table.c.ip_proto == bindparam('proto')),
                order_by = [desc(flow_table.c.starttime)]).compile()

    def _init_pcap(self, file):
        self.p = pcap.pcap(file)
        self.p.setfilter("host %s" % self.hp)
                
    def run(self):
        """Iterate over a pcap object""" 
        self.engine.begin()
        for ts, buf in self.p:
            self.packet_handler(ts, buf)
        self.write_db()    
        self.engine.commit()
        print '\tRead %s packets at %s' % (self.count, asctime())
        
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

    def update_in_cache(self, cache, key, ts, length):
        """
        Look for flow identified by key in cache cache. 
        Update flow if it needs updating, allowing for times.
        Return True if we update a flow, False otherwise
        """                  
        if not cache.has_key(key): 
            return False
        ts_dt = datetime.fromtimestamp(ts) 
        for i in xrange(0, len(cache[key])):                             
            if cache[key][i]['lastseen'] > datetime.fromtimestamp(ts-FLOW_DELTA): 
                cache[key][i]['lastseen'] = ts_dt
                cache[key][i]['bytes'] += length;
                cache[key][i]['packets'] += 1;  
                return True       
        return False

    def match_flow(self, ts, src, dst, sport, dport, proto, length):
        """
        have we seen matching flow in this pcap file/already? 
        If we've seen in in this before, update cache, otherwise try and match in db
        If that doesn't match, then create new object
        """      
        self.count += 1    
        key = (src, dst, sport, dport, proto)
        if not self.count % LOAD_QUANTA:
            self.write_db()     
            self.engine.commit()
            self.engine.begin()
            print '\tRead %s packets at %s' % (self.count, asctime())
        ts_dt = datetime.fromtimestamp(ts)  
        if self.update_in_cache(self.new_flows, key, ts, length):  
            return               
        if self.update_in_cache(self.updated_flows, key, ts, length):
            return
        srcid = Ip.id_get_or_create(src)
        dstid = Ip.id_get_or_create(dst)  
        flows = self.fq.execute(srcid=srcid, dstid=dstid, sport=sport,
                                dport=dport, proto=proto, timedelta=datetime.fromtimestamp(ts-FLOW_DELTA)).fetchall()
        if flows:
            # exists in db   
            flow = dict(flows[0])    # if more than one, append data to the last seen flow
            if flow['starttime'] == ts_dt:
                raise DuplicateFlow
            else:      
                flow['bytes'] += length; 
                flow['packets'] += 1     
                flow['lastseen'] = ts_dt
                self.updated_flows.setdefault(key, [])
                self.updated_flows[key].append(flow)  
        else:             
            # new flow  
            flow = dict(honeypot_id=self.hpid, ip_proto=proto, src_id=srcid, dst_id=dstid, sport=sport, dport=dport, 
                        starttime=ts_dt, lastseen=ts_dt, packets=1, bytes=length, filename=self.filename)
            self.new_flows.setdefault(key, [])
            self.new_flows[key].append(flow)  

    def decode_packet(self, buf):
        """extract basic info (src, dst, sport, dport, length) from a packet and return the data"""
        pkt = dpkt.ethernet.Ethernet(buf)
        subpkt = pkt.data
        if pkt.type != 2048:
            # non IP. Ignore
            raise DecodeError
        else:
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

    def write_db(self):
        """write data to db"""
        insert_list = []             
        update_list = []             
        for v in self.new_flows.values(): 
            for f in v:
                insert_list.append(f)
        for v in self.updated_flows.values():
            for f in v:
                update_list.append(f)
        save_table(flow_table, insert_list)
        self.new_flows = {}
        if update_list:
            flow_table.update(flow_table.c.id==bindparam('id')).execute(update_list)
            self.updated_flows = {}