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

import re
import sys
import socket
import string
import dpkt
import pcap

from base import Base
from output import stringFormatMessage

class wordSearch(Base):
    """
    wordSeach is an auxillary of pcapRE. It allows you to pass a list of words 
    you wish to search for to pcapRE.
    """
    def __init__(self):
        Base.__init__(self)
        self.results = {}
        self.words = []
        format = "%-10(word)s %-5(proto)s %-17(source)s %-17(dest)s %-7(dport)s %10(count)s\n"
        self.msg = stringFormatMessage(format=format)
        
    def findWords(self, data, key):
        for w in self.words:
            if string.find(data, w) >= 0:
                if key is not None:
                    if key not in self.results[w]:
                        self.results[w][key] = 0 
                    self.results[w][key] += 1
                
    def setWords(self, wordstr):
        self.words = []
        for w in wordstr.split(" "):
            self.results[w] = {}
            self.words.append(w)

    def printResults(self, f=sys.stdout):
        self.writeResults(sys.stdout)

    def writeResults(self, f=sys.stdout):
        self.doOutput("Word Matches\n")
        self.doOutput("%-10s %-5s %-17s %-17s %-7s %10s\n" % ("WORD", "PROTO", "SOURCE", "DEST", "DPORT", "COUNT"))
        for word, cons in self.results.items():
            for k in cons:
                self.doOutput("%-10s %-5s %-17s %-17s %-7s %10s\n" % (word, k[0], k[1], k[2], k[3], self.results[word][k]))


class pcapRE(Base):
    """
    Takes a pcapObj as an argument.
    """
    def __init__(self, pcapObj):
        Base.__init__(self)
        self.exp = None
        self.p = pcapObj
        self.results = {}
        self.doWordSearch = 0
        format = "%-10(pattern)s %-5(proto)s %-15(source)s %-15(dest)s %-5(dport)s %10(count)s\n"
        self.msg = stringFormatMessage(format=format)
        
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
        """Iterate over a pcap object"""
        for ts, buf in self.p:
            self.packetHandler(ts, buf)

    def packetHandler(self, ts, buf):   
        """Process a pcap packet buffer""" 
        pay = None
        m = None
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
                pay = tcp.data
                dport = tcp.dport
                key = (proto, shost, dhost, dport)
            if proto == socket.IPPROTO_UDP:
                udp = subpkt.data
                pay = udp.data
                dport = udp.dport
                key = (proto, shost, dhost, dport)
        except dpkt.Error:
            return
        if pay is not None and self.exp is not None:
            m = self.exp.search(pay)
            if m:
                if key not in self.results:
                    self.results[key] = 0
                self.results[key] += 1
                if self.doWordSearch:
                    self.searcher.findWords(pay, key)
    
    def printResults(self):
        self.writeResults(sys.stdout)

    def writeResults(self, f=sys.stdout):
        """Write results to a given filehandle"""
        self.doOutput("%-10s %-5s %-15s %-15s %-5s %10s\n" % ("PATTERN", "PROTO", "SOURCE", "DEST", "DPORT", "COUNT"))
        for key, val in self.results.items():
            self.doOutput("%-10s %-5s %-15s %-15s %-5s %10s\n" % (self.pattern, key[0], key[1], key[2], key[3], val))
        if self.doWordSearch:
            self.searcher.writeResults()
