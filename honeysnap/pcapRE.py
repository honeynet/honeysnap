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
  
class pcapReError(Exception):
    pass

class pcapRE(Base):
    """
    Takes a pcapObj as an argument.
    """
    def __init__(self, pcapObj):
        Base.__init__(self)
        self.exp = None
        self.p = pcapObj    
        self.action = None
        self.doWordSearch = 0                                
        format = "%(pattern)-10s %(proto)-5s %(source)-15s %(dest)-15s %(dport)-5s %(count)10s\n"  
        self.msg = stringFormatMessage(format=format)        
        
    def setRE(self, pattern):
        """
        Arg is a string that will be treated as a regular expression
        """
        self.exp = re.compile(pattern)
        self.pattern = pattern

    def setFilter(self, filter):
        self.p.setfilter(filter)
   
    def setAction(self, action):
        self.action=action

    def setWordSearch(self, searcher):
        """ Takes an instance of class wordSearch as arg"""
        self.doWordSearch = 1
        self.searcher = searcher
        
    def start(self):
        """Iterate over a pcap object"""  
        if not self.action:
            raise pcapReError('Action not set (use setAction)')  
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
            if proto == socket.IPPROTO_UDP:
                udp = subpkt.data
                pay = udp.data
                dport = udp.dport
        except dpkt.Error:
            return        
        if pay is not None and self.exp is not None:
            m = self.exp.search(pay)
            if m:                   
                self.action(m, proto, shost, dhost, dport, pay)
     
class pcapReCounter(pcapRE):
    """Extension of pcapRE to do simple counting of matching packets"""
    def __init__(self, pcapObj):
        pcapRE.__init__(self, pcapObj) 
        self.results = {}          
        self.action = self.simpleCounter

    def simpleCounter(self, m, proto, shost, dhost, dport, pay):
        """Simple action that just counts matches"""  
        key = (proto, shost, dhost, dport) 
        if key not in self.results:
            self.results[key] = 0
        self.results[key] += 1
        if self.doWordSearch:
            self.searcher.findWords(pay, key)
    
    def writeResults(self):
        """Summarise results for simpleCounter()"""  
        if self.results:     
            self.msg.msg=dict(pattern="PATTERN", proto="PROTO", source="SOURCE", dest="DEST", dport="DPORT", count="COUNT")
            self.doOutput(self.msg)
            for key, val in self.results.items():
                self.msg.msg=dict(pattern=self.pattern, proto=key[0], source=key[1], dest=key[2], dport=key[3], count=val)
                self.doOutput(self.msg)  
        else:
            self.doOutput('No matching packets found\n')
        if self.doWordSearch:  
            self.searcher.writeResults()   
     
class wordSearch(Base):
    """
    wordSeach is an auxillary of pcapReCounter. It allows you to pass a list of words 
    you wish to search for to pcapRE.
    """
    def __init__(self):
        Base.__init__(self)
        self.results = {}
        self.words = []
        format = "%(word)-10s %(proto)-5s %(source)-17s %(dest)-17s %(dport)-7s %(count)10s\n"
        self.msg = stringFormatMessage(format=format)

    def findWords(self, data, key):
        for w in self.words:
            if string.find(data, w) >= 0:
                if key is not None:
                    if not self.results.has_key(w):
                        self.results[w] = {}
                    if key not in self.results[w]:
                        self.results[w][key] = 0 
                    self.results[w][key] += 1

    def setWords(self, wordstr):
        self.words = []
        for w in wordstr.split(" "):
            #self.results[w] = {}
            self.words.append(w)

    def writeResults(self):  
        """Summarise results"""
        if self.results:
            #self.doOutput("Word Matches\n")      
            self.msg.msg=dict(word="WORD", proto="PROTO", source="SOURCE", dest="DEST", dport="DPORT", count="COUNT")
            self.doOutput(self.msg)
            for word, cons in self.results.items():
                for k in cons: 
                    self.msg.msg = dict(word=word, proto=k[0], source=k[1], dest=k[2], dport=k[3], count=self.results[word][k])
                    self.doOutput(self.msg)   
        else:
             self.doOutput("No words found\n")
              