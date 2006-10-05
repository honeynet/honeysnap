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

import pcapy
import base
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

class Summarize(base.Base):
    """
    Summarize takes a pcapObj, and an optional dbObj that is a mysql db connection.
    This class reads the pcap data, hands it to a decoder, and then keys each packet
    by (srcip, dstip, dport).  The count of each tuple is kept. 
    Utimately you get a packet count for each outgoing connection.
    This class works best if you use setFilter to filter by "src $HONEYPOT"
    """
    def __init__(self, pcapObj, dbObj):
        self.tcpports = {}
        self.udpports = {}
        self.icmp = {}
        self.p = pcapObj
        if dbObj:
            self.db = summaryTable(dbObj)
        else:
            self.db =None
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.p.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

    def setFilter(self, filter, file):
        self.filter = filter
        self.file = file
        self.p.setfilter(filter)

    def start(self):
        self.p.dispatch(-1, self.packetHandler)
        #self.printResults()

    def packetHandler(self, hdr, data):
        #print self.decoder.decode(data)
        try:
            pkt = self.decoder.decode(data)
        except:
            return
        try:
            proto = pkt.child().child().protocol
            shost = pkt.child().get_ip_src()
            dhost = pkt.child().get_ip_dst()
        except: 
            return

        try:
            if proto == socket.IPPROTO_TCP:
                dport = pkt.child().child().get_th_dport()
                sport = pkt.child().child().get_th_sport()
                key = (shost, dhost, dport)
                if key not in self.tcpports:
                    self.tcpports[key] = 0
                self.tcpports[key] += 1
                if self.db:
                    self.db.queueInsert((proto, ipnum(shost), sport, ipnum(dhost), dport, self.filter, self.file, hdr.getts()[0], self.tcpports[key])) 
            if proto == socket.IPPROTO_UDP:
                dport = pkt.child().child().get_uh_dport()
                sport = pkt.child().child().get_uh_sport()
                key = (shost, dhost, dport)
                if key not in self.udpports:
                    self.udpports[key] = 0
                self.udpports[key] += 1
                if self.db:
                    self.db.queueInsert((proto, ipnum(shost), sport, ipnum(dhost), dport, self.filter, self.file, hdr.getts()[0], self.udpports[key])) 
        except:
            return

    def printResults(self):
        print "TCP TRAFFIC SUMMARY:"
        print "%-15s %-15s %8s %10s" % ("SOURCE", "DEST", "DPORT", "COUNT")
        for key, val in self.tcpports.items():
            if val > 10:
                print "%-15s %-15s %8s %10s" % (key[0], key[1], key[2], val)
        if len(self.udpports) > 0:
            print "UDP TRAFFIC SUMMARY:"
            print "%-15s %-15s %8s %10s" % ("SOURCE", "DEST", "DPORT", "COUNT")
            for key, val in self.udpports.items():
                if val > 10:
                    print "%-15s %-15s %8s %10s" % (key[0], key[1], key[2], val)
    
    def writeResults(self):
        f = sys.stdout
        #f = open(self.outfile, 'a')
        f.write("TCP TRAFFIC SUMMARY:\n")
        f.write("%-15s %-15s %8s %10s\n" % ("SOURCE", "DEST", "DPORT", "COUNT"))
        for key, val in self.tcpports.items():
            #if val > 10:
            f.write("%-15s %-15s %8s %10s\n" % (key[0], key[1], key[2], val))
        if len(self.udpports) > 0:
            f.write("UDP TRAFFIC SUMMARY:\n")
            f.write("%-15s %-15s %8s %10s\n" % ("SOURCE", "DEST", "DPORT", "COUNT"))
            for key, val in self.udpports.items():
                #if val > 10:
                f.write("%-15s %-15s %8s %10s\n" % (key[0], key[1], key[2], val))
        #f.close()
        if self.db:
            self.db.doInserts()
                
