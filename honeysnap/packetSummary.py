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
import dpkt
import base
import socket
import sys
import time
from util import make_dir  
from singletonmixin import HoneysnapSingleton

class Summarize(base.Base):
    """
    Summarize takes a pcapObj
    This class reads the pcap data, hands it to a decoder, and then keys each packet
    by (srcip, dstip, dport).  The count of each tuple is kept.
    Utimately you get a packet count for each outgoing connection.
    This class works best if you use setFilter to filter by "src $HONEYPOT"
    """
    def __init__(self, pcapObj, verbose=0): 
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.tcpports = {}
        self.udpports = {}
        self.icmp = {}
        self.p = pcapObj
        self.verbose = verbose
        self.outdir = ""
        self.tf = options['time_convert_fn']  
        

    def setFilter(self, filter, file):
        self.filter = filter
        self.file = file
        self.p.setfilter(filter)

    def setOutdir(self, dir):
        make_dir(dir)
        self.outdir = dir

    def start(self):
        """Iterate over a pcap object"""
        for ts, buf in self.p:
            self.packetHandler(ts, buf)

    def packetHandler(self, ts, buf):
        """Process a pcap packet buffer"""
        try:
            pkt = dpkt.ethernet.Ethernet(buf)
            subpkt = pkt.data
            if type(subpkt) != type(dpkt.ip.IP()):
                # skip non IP packets
                return
            proto = subpkt.p
            shost = socket.inet_ntoa(subpkt.src)
            dhost = socket.inet_ntoa(subpkt.dst)
        except dpkt.Error:
            return
        try:
            if proto == socket.IPPROTO_TCP:
                tcp = subpkt.data
                dport = tcp.dport
                sport = tcp.sport
                if self.verbose:
                    key = (shost, dhost, dport, sport)
                else:
                    key = (shost, dhost, dport)
                if key not in self.tcpports:
                    # tuple is [start time, end time, count, bytes]
                    self.tcpports[key] = [ts, 0, 0, 0]
                self.tcpports[key][1] = ts
                self.tcpports[key][2] += 1
                self.tcpports[key][3] += len(tcp.data)
            if proto == socket.IPPROTO_UDP:
                udp = subpkt.data
                dport = udp.dport
                sport = udp.sport
                if self.verbose:
                    key = (shost, dhost, dport, sport)
                else:
                    key = (shost, dhost, dport)
                if key not in self.udpports:
                    # tuple is [start time, end time, count, bytes]
                    self.udpports[key] = [ts, 0, 0, 0]
                self.udpports[key][1] = ts
                self.udpports[key][2] += 1
                self.udpports[key][3] += len(udp.data)
        except dpkt.Error:
            return

    def printResults(self):
        if self.verbose:
            self.writeResults(limit=0)
        else:
            self.writeResults(limit=10)

    def writeResults(self, limit=0):
        """Write results. Optionally only print more significant options""" 
        
        if len(self.tcpports) == 0:
            self.doOutput("No TCP traffic seen\n")
        else:
            self.doOutput("\nTCP TRAFFIC SUMMARY:\n\n")
            if self.verbose:
                self.doOutput("%-20s %-20s %-16s %-6s %-16s %-6s %10s %10s\n" % ("Start", "End", "Source", "Sport", "Dest", "Dport", "Count", "Bytes"))
            else:
                self.doOutput("%-20s %-20s %-16s %-16s %8s %10s %10s\n" % ("Start", "End", "Source", "Dest", "Dport", "Count", "Bytes"))
            for key, val in self.tcpports.iteritems():
                if val[2] > limit:
                    if self.verbose:
                        self.doOutput("%-20s %-20s %-16s %-6s %-16s %-6s %10s %10s\n" % (self.tf(val[0]), self.tf(val[1]), key[0], key[3], key[1], key[2], str(val[2]), str(val[3])))
                    else:
                        self.doOutput("%-20s %-20s %-16s %-16s %8s %10s %10s\n" % (self.tf(val[0]), self.tf(val[1]), key[0], key[1], key[2], str(val[2]), str(val[3])))
                        
        if len(self.udpports) == 0:
            self.doOutput("No UDP traffic seen\n")
        else:
            self.doOutput("\n\nUDP TRAFFIC SUMMARY:\n\n")
            if self.verbose:
                self.doOutput("%-20s %-20s %-16s %-6s %-16s %-6s %10s %10s\n" % ("Start", "End", "Source", "Sport", "Dest", "Dport", "Count", "Bytes"))
            else:
                self.doOutput("%-20s %-20s %-16s %-16s %8s %10s %10s\n" % ("Start", "End", "Source", "Dest", "Dport", "Count", "Bytes"))
            for key, val in self.udpports.iteritems():
                if val[2] > limit:
                    if self.verbose:
                        self.doOutput("%-20s %-20s %-16s %-6s %-19s %-6s %10s %10s\n" % (self.tf(val[0]), self.tf(val[1]), key[0], key[3], key[1], key[2], str(val[2]), str(val[3])))
                    else:
                        self.doOutput("%-20s %-20s %-16s %-16s %8s %10s %10s\n" % (self.tf(val[0]), self.tf(val[1]), key[0], key[1], key[2], str(val[2]), str(val[3])))
                  
                   

