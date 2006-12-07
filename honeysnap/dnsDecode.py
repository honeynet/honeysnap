################################################################################
# (c) 2006, The Honeynet Project
#   Authors: Arthur Clune and David Barroso (tomac@yersinia.net)
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

import struct, dpkt, time, re
import base
from singletonmixin import HoneysnapSingleton
import pcap
from socket import inet_ntoa
import sys
from util import make_dir          

from socket import inet_ntoa

class dnsDecode(base.Base):
    
    def __init__(self, hp, direction="queried"):
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.p = pcap.pcap(options["tmpf"], promisc=False)     
        self.direction = direction
        if direction == "queried":
            self.p.setfilter("(src host %s and udp and dst port 53) or (dst host %s and udp and src port 53)" % (hp, hp))
        else:
            self.p.setfilter("(dst host %s and udp and dst port 53) or (src host %s and udp and src port 53)" % (hp, hp))
        self.log = {}
        self.fp = sys.stdout   
        self.timefn = options['time_convert_fn']
    
    def setOutdir(self, dir):
        make_dir(dir)             
        if self.direction == "queried":   
            self.fp = open(dir + "/dns_queries.txt", "w")
        else:                          
            self.fp = open(dir + "/dns_served.txt", "w")
    
    def packetHandler(self, ts, ip, payload):
        """ts timestamp, ip dpkt.ip.IP, payload = dns udp data"""    
        # this is very basic
        # dpkt extracts many more types                      
        try:
            msg = dpkt.dns.DNS(payload)
        except dpkt.Error:    
            return
        if msg.rcode == dpkt.dns.DNS_RCODE_NOERR and len(msg.an)>0:
            #print 'msg is %s' % `msg`
            queried     = msg.qd[0].name
            #additional  = [x.name for x in msg.ar]
            #authorities = [x.name for x in msg.ns]
            answers = []
            for an in msg.an:
                if an.type == dpkt.dns.DNS_A:
                    answers.append(inet_ntoa(an.ip))
                if an.type == dpkt.dns.DNS_PTR:
                    answers.append(an.ptrname)
            line = "%s, Query %s, answer %s\n" % (self.timefn(ts), queried, ", ".join(answers))
            #self.doOutput("\t%s" % line)
            self.fp.write(line)
        else:   
            # question. Fix this later
            pass
    
    def run(self):
        # since we set a filter on pcap, all the
        # packets we pull should be handled
        for ts, buf in self.p:    
            try:
                ip = dpkt.ethernet.Ethernet(buf).data 
                self.packetHandler(ts, ip, ip.data.data)
            except dpkt.Error:
                continue        

