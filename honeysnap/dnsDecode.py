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

class dnsDecode(base.Base):
    
    def __init__(self, hp):
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.p = pcap.pcap(options["tmpf"], promisc=False)
        self.p.setfilter("host %s and udp port 53" % (hp))
        self.log = {}
        self.fp = sys.stdout
    
    def setOutdir(self, dir):
        make_dir(dir)
        self.fp = open(dir + "/dns.txt", "w")
    
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
            line = "\tQuery %s, answer %s\n" % (queried, answers)
            #self.doOutput(line)
            self.fp.write(line)
    
    def run(self):
        # since we set a filter on pcap, all the
        # packets we pull should be handled
        for ts, buf in self.p:
            ip = dpkt.ethernet.Ethernet(buf).data
            payload = ip.data.data
            try:
                self.packetHandler(ts, ip, payload)
            except dpkt.Error:
                continue        


