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

from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import pcapy
import re
import sys
import socket
import string

import base

class wordSearch(base.Base):
    """
    wordSeach is an auxillary of pcapRE. It allows you to pass a list of words 
    you wish to search for to pcapRE.
    """
    def __init__(self):
        self.results = {}
        self.words = []

    def _buildkey(self, pkt):
        try:
            proto = pkt.child().child().protocol
            if proto == socket.IPPROTO_TCP:
                ip = pkt.child()
                shost = ip.get_ip_src()
                dhost = ip.get_ip_dst()
                tcp = pkt.child().child()
                dport = tcp.get_th_dport()
                key = (proto, shost, dhost, dport)
            if proto == socket.IPPROTO_UDP:
                ip = pkt.child()
                shost = ip.get_ip_src()
                udp = pkt.child().child()
                dport = udp.get_uh_dport()
                key = (proto, shost, dhost, dport)
        except:
            return
        return key
        
    def findWords(self, pkt, data):
        for w in self.words:
            if string.find(data, w) >= 0:
                key = self._buildkey(pkt)
                if key is not None:
                    if key not in self.results[w]:
                        self.results[w][key] = 0 
                    self.results[w][key] += 1
                
    def setWords(self, wordstr):
        self.words = []
        for w in wordstr.split(" "):
            self.results[w] = {}
            self.words.append(w)

    def printResults(self):
        for word, cons in self.results.items():
            for k in cons:
                print "%s: %s\t\t%s\t\t%s\t\t%s\t\t\t%s" % (word, k[0], k[1], k[2], k[3], self.results[word][k])

    def writeResults(self):
        f = sys.stdout
        #f = open(self.outfile, 'a')
        f.write("Word Matches\n")
        f.write("%-10s %-5s %-17s %-17s %-7s %10s\n" % ("WORD", "PROTO", "SOURCE", "DEST", "DPORT", "COUNT"))
        for word, cons in self.results.items():
            for k in cons:
                f.write("%-10s %-5s %-17s %-17s %-7s %10s\n" % (word, k[0], k[1], k[2], k[3], self.results[word][k]))
        #f.close()


class pcapRE(base.Base):
    """
    Takes a pcapObj as an argument.
    """
    def __init__(self, pcapObj):
        self.exp = None
        self.p = pcapObj
        self.results = {}
        self.doWordSearch = 0
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.p.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

    def setRE(self, pattern):
        """
        Arg is a string that will be treated as a regular expression
        """
        self.exp = re.compile(pattern)
        self.pattern = pattern

    def setFilter(self, filter):
        self.p.setfilter(filter)

    def setWordSearch(self, searcher):
        """ Takes an instance of class wordSearch as arg"""
        self.doWordSearch = 1
        self.searcher = searcher
        
    def start(self):
        self.p.dispatch(-1, self.packetHandler)
        #self.printResults()

    def packetHandler(self, hdr, data):
        pay = None
        m = None
        try:
            pkt = self.decoder.decode(data)
        except:
            return
        try:
            proto = pkt.child().child().protocol
        except:
            return
        try:
            if proto == socket.IPPROTO_TCP:
                ip = pkt.child()
                shost = ip.get_ip_src()
                dhost = ip.get_ip_dst()
                tcp = pkt.child().child()
                pay = tcp.child().get_buffer_as_string()
                dport = tcp.get_th_dport()
                key = (proto, shost, dhost, dport)
            if proto == socket.IPPROTO_UDP:
                ip = pkt.child()
                shost = ip.get_ip_src()
                dhost = ip.get_ip_dst()
                udp = pkt.child().child()
                pay = udp.child().get_buffer_as_string()
                dport = udp.get_uh_dport()
                key = (proto, shost, dhost, dport)
        except:
            return
        if pay is not None and self.exp is not None:
            m = self.exp.search(pay)
            if m:
                if key not in self.results:
                    self.results[key] = 0
                self.results[key] += 1
                if self.doWordSearch:
                    self.searcher.findWords(pkt, pay)
    
    def printResults(self):
        for key, val in self.results.items():
            print "Pattern: %-10s %-5s %-15s %-15s %-5s %10s" % (self.pattern, key[0], key[1], key[2], key[3], val)
        if self.doWordSearch:
            #self.searcher.printResults()
            self.searcher.writeResults()

    def writeResults(self):
        f = sys.stdout
        #f = open(self.outfile, 'a')
        f.write("%-10s %-5s %-15s %-15s %-5s %10s\n" % ("PATTERN", "PROTO", "SOURCE", "DEST", "DPORT", "COUNT"))
        for key, val in self.results.items():
            f.write("%-10s %-5s %-15s %-15s %-5s %10s\n" % (self.pattern, key[0], key[1], key[2], key[3], val))
        if self.doWordSearch:
            self.searcher.writeResults()
        #f.close()
