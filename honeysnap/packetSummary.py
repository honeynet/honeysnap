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

class Summarize(base.Base):
    """
    Summarize takes a pcapObj, and an optional dbObj that is a mysql db connection.
    This class reads the pcap data, hands it to a decoder, and then keys each packet
    by (srcip, dstip, dport).  The count of each tuple is kept. 
    Utimately you get a packet count for each outgoing connection.
    This class works best if you use setFilter to filter by "src $HONEYPOT"
    """
    def __init__(self, pcapObj, dbObj=None):
        self.tcpports = {}
        self.udpports = {}
        self.icmp = {}
        self.p = pcapObj
        if dbObj:
            self.db = summaryTable(dbObj)
        else:
            self.db = None

    def setFilter(self, filter, file):
        self.filter = filter
        self.file = file
        self.p.setfilter(filter)

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
                key = (shost, dhost, dport)
                if key not in self.tcpports:
                    self.tcpports[key] = 0
                self.tcpports[key] += 1
                if self.db:
                    self.db.queueInsert((proto, ipnum(shost), sport, ipnum(dhost), dport, self.filter, self.file, hdr.getts()[0], self.tcpports[key])) 
            if proto == socket.IPPROTO_UDP:
                udp = subpkt.data
                dport = udp.dport
                sport = udp.sport
                key = (shost, dhost, dport)
                if key not in self.udpports:
                    self.udpports[key] = 0
                self.udpports[key] += 1
                if self.db:
                    self.db.queueInsert((proto, ipnum(shost), sport, ipnum(dhost), dport, self.filter, self.file, hdr.getts()[0], self.udpports[key])) 
        except dpkt.Error:
            return

    def printResults(self):
        self.writeResults(sys.stdout, limit=10)
    
    def writeResults(self, f=sys.stdout, limit=0):
        """Write results to a given filehandle. Optionally only print more significant options"""
        f.write("TCP TRAFFIC SUMMARY:\n")
        f.write("%-15s %-15s %8s %10s\n" % ("SOURCE", "DEST", "DPORT", "COUNT"))
        for key, val in self.tcpports.items():
            if val > limit:
                f.write("%-15s %-15s %8s %10s\n" % (key[0], key[1], key[2], val))
        if len(self.udpports) > 0:
            f.write("UDP TRAFFIC SUMMARY:\n")
            f.write("%-15s %-15s %8s %10s\n" % ("SOURCE", "DEST", "DPORT", "COUNT"))
            for key, val in self.udpports.items():
                if val > limit:
                    f.write("%-15s %-15s %8s %10s\n" % (key[0], key[1], key[2], val))
        if self.db:
            self.db.doInserts()
                
