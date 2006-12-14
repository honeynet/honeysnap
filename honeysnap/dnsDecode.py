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

from socket import inet_ntoa, inet_ntop, AF_INET6

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
        self.tf = options['time_convert_fn']
    
    def setOutdir(self, dir):
        make_dir(dir)             
        if self.direction == "queried":   
            self.fp = open(dir + "/dns_queries.txt", "w")
        else:                          
            self.fp = open(dir + "/dns_served.txt", "w")
    
    def packetHandler(self, ts, ip, payload):
        """ts timestamp, ip dpkt.ip.IP, payload = dns udp data"""    
        try:                    
            msg = dpkt.dns.DNS(payload)  
            srcip = inet_ntoa(ip.src)
        except dpkt.Error:    
            return
        except (IndexError, TypeError):
            # dpkt shouldn't do this, but it does in some cases
            return
        if msg.qr == dpkt.dns.DNS_A and msg.rcode == dpkt.dns.DNS_RCODE_NOERR and len(msg.an)>0:
            queried = "%s for " % srcip
            if msg.qd[0].type == dpkt.dns.DNS_A:
                queried = queried + "%s (A)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_NS:
                queried = queried + "%s (NS)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_CNAME:
                queried = queried + "%s (CNAME)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_SOA:
                queried = queried + "%s (SOA)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_PTR:
                queried = queried + "%s (PTR)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_HINFO:
                queried = queried + "%s (HINFO)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_MX:
                queried = queried + "%s (MX)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_TXT: 
                queried = queried + "%s (TXT)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_AAAA:            
                queried = queried + "%s (AAAA)" % (msg.qd[0].name)
            if msg.qd[0].type == dpkt.dns.DNS_SRV:
                queried = queried + "%s (SRV)" % (msg.qd[0].name)     

            answers = []
            for an in msg.an:
                if an.type == dpkt.dns.DNS_A:
                    answers.append(inet_ntoa(an.ip))
                elif an.type == dpkt.dns.DNS_PTR:
                    answers.append(an.ptrname)
                elif an.type == dpkt.dns.DNS_NS:
                    answers.append(an.nsname)
                elif an.type == dpkt.dns.DNS_CNAME:
                    answers.append(an.cname)
                elif an.type == dpkt.dns.DNS_SOA:
                    answers.append(an.mname)
                    answers.append(an.rname)
                    answers.append(str(an.serial))
                    answers.append(str(an.refresh))
                    answers.append(str(an.retry))
                    answers.append(str(an.expire))
                    answers.append(str(an.minimum)) 
                elif an.type == dpkt.dns.DNS_HINFO:
                    answers.append(an.text)
                elif an.type == dpkt.dns.DNS_MX:
                    answers.append(an.mxname)
                elif an.type == dpkt.dns.DNS_TXT:
                    answers.append(an.rdata) 
                elif an.type == dpkt.dns.DNS_AAAA:
                    answers.append(inet_ntop(AF_INET6,an.ip6))
                elif an.type == dpkt.dns.DNS_SRV:
                    # do something with SRV
                    pass
                else:
                    # un-handled type
                    answers.append("[Honeysnap: Undecoded response]")
                    continue
            line = "%s, Queried %s, answer %s\n" % (self.tf(ts), queried, ", ".join(answers))
            #self.doOutput("\t%s" % line)
            self.fp.write(line)
        else:   
            # question.   
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

