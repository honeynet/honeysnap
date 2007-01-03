################################################################################
# (c) 2006, The Honeynet Project
#   Author: Jed Haile jed@honeynet.org
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

# $Id: dnsDecode.py 4874 2006-12-05 15:48:41Z arthur $

import struct, dpkt, time, re
import base
from singletonmixin import HoneysnapSingleton
import pcap
from socket import inet_ntoa
import sys
from util import make_dir

class telnetDecode(base.Base):

    def __init__(self, hp):
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.p = pcap.pcap(options["tmpf"], promisc=False)
        self.p.setfilter("host %s and tcp port 23" % (hp))
        self.log = {}
        self.fp = sys.stdout
        self.outdir = None

    def setOutdir(self, dir):
        self.outdir = dir
        make_dir(dir)
        #self.fp = open(dir + "/telnet.txt", "w")

    def packetHandler(self, ts, ip, payload):
        try:
            lines, options = dpkt.telnet.strip_options(payload)
            #print options, lines
        except dpkt.Error:
            return
        for line in lines:
            self.fp.write("%s\n" % line)

    def run(self):
        # since we set a filter on pcap, all the
        # packets we pull should be handled
        d = {}
        for ts, buf in self.p:
            ip = dpkt.ethernet.Ethernet(buf).data
            fn = "/%s:%d->%s:%d" % (inet_ntoa(ip.src),ip.tcp.sport, inet_ntoa(ip.dst), ip.tcp.dport)
            payload = ip.data.data
            buf = d.setdefault(fn, "")
            if len(buf):
                d[fn] = buf+payload
            else:
                d[fn] = payload
        #print len(d)
        for k,v in d.iteritems():
            #print self.outdir+k
            fp = open(self.outdir+k, 'w')
            lines, options = dpkt.telnet.strip_options(v)
            lines = "\n".join(lines)
            fp.write(lines)
            fp.flush()
            fp.close()
            """
            try:
                self.packetHandler(ts, ip, payload)
            except dpkt.Error:
                continue
            """
