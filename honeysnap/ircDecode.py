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

from hsIRC import HoneySnapIRC   
from singletonmixin import HoneysnapSingleton
import math 
import os
import time    
import sys
import re
#import dnet
from util import orderByValue, make_dir
from base import Base
from output import stringMessage


# global bot word list.
botprefixes = [".", "-", "!", "\`",  "\\", "|"]
botcoms = ["die ", "esay ", "flood ", "m ", "me ", "part ", "payment ", "ping ", "s ", "say ", "server ",
        "services ", "startflood ", "stopflood ", "x ", "antiaction ", "antibold ", "anticolour ", "antinotice ",
        "antipub ", "antirepeat ", "antireverse ", "antiunderline ", "antiurl ", "autovoice ", "chanserv ", 
        "cycle ", "dynamicexempts ", "dynamicinvites ", "enforcetopiclimit ", "nodesynch ", "locked ",
        "noop ", "op ", "passive ", "private ", "revenge ", "revengebot ", "secret ", "seen ", "seen ",
        "shared ", "stats ", "strictop ", "suspended ", "topic ", "userexempts ", "userinvites ", "voice "]

botwords = []
for i in botprefixes:
    tmp = [i+w for w in botcoms]
    botwords += tmp

# global wordlist. Added to via words file in __init__
words = ['0day', 'access', 'account', 'admin','auth', 'bank', 'bash', '#!/bin', 'binaries', 'binary', 'bot',
    'card', 'cash', 'cc', 'cent', 'connect', 'crack',
    'credit' ,'dns', 'dollar', 'ebay', 'e-bay', 'egg', 'flood', 'ftp', 'hackexploit', 'http', 'install', 'leech', 'login', 
    'money', '/msg', 'nologin', 'owns', 'ownz', 'password',
    'paypal', 'phish', 'pirate', 'pound', 'probe', 'prv', 'putty', 'remote', 'resolved', 'root', 'rooted', 
    'scam', 'scan', 'shell', 'smtp', 'sploit', 'sterling',
    'sucess', 'sysop', 'sys-op', 'trade', 'uid', 'uname', 'uptime', 'userid', 'virus', 'warez']   
 
class ircDecode(Base):
    """
    IRC analysis:
    * number of messages
    * messages matching patterns
          * static patterns
          * regex patterns
          * possible bot commands

    * spot lines repeated N times (N=100 seems to work well) to spot
        botnets reporting back

    * number of users
    * top N users

    * number of channels
    * top N channels

    * IP addresses of irc talkers
    * top N ips
    """

    def __init__(self):        
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        Base.__init__(self)
        self.cmds = {}
        self.sources = {}
        self.targets = {}
        self.ips = {}
        self.users = {}
        self.channels = {}
        self.repeats = {}
        self.lines = {}      
        self.botwords = botwords
        self.words = words
        self.wordlines = []
        self.botlines = []
        self.privcount = 0     
        self.dir = ""
        self.fp = sys.stdout   
        self.limit=options['irc_limit']     
        self.tf = options['time_convert_fn']
        self.wordfile=options['wordfile'] 
        if self.wordfile:
            if os.path.exists(self.wordfile) and os.path.isfile(self.wordfile):
                wfp = open(self.wordfile, 'rb')
                filewords = wfp.readlines()
                filewords = [w.strip() for w in filewords]
                self.words = self.words + filewords 
            else:
                print "Can't open specified wordlist %s. Stopping" % self.wordfile
                print "Please check the existence of the wordfile, or delete the WORDFILE option from the config if it's not wanted"
                sys.exit(1)
         
    def printLines(self, c, e):        
        """Simple print method"""
        if e.eventtype() != 'ping' and e.eventtype() != 'all_raw_messages':   
            self.fp.write("%s\t%s:%s -> %s:%s\t%s\t%s\t%s\t%s\n" % (self.tf(e.time), e.src, e.sport, e.dst, e.dport,
                                         e.eventtype(), e.source(),
                                         e.target(), ' '.join(e.arguments())))
             
    def setOutdir(self, dir):
        """
        Set output directory for IRC log
        If you just want output to stdout, don't call this function
        """
        make_dir(dir) 
        self.dir = dir
        
    def setOutfile(self, filename):
        """
        Set output filename for IRC log
        If you just want output to stdout, don't call this function
        """
        if self.dir:
            self.fp = open(self.dir + "/%s" % filename, "w")  
        else:
            raise IOError("Cannot create file %s - directory not specified" % filename) 
    
    def decodeCB(self, c, e):
        """
        Callback to register with HoneySnapIRC
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        """
        if e.eventtype() not in ['ping', 'pong'] and e.eventtype() != 'all_raw_messages':
            cmd = e.eventtype()
            source = e.source()
            target = e.target()
            if cmd not in self.cmds:
                self.cmds[cmd] = 0
            self.cmds[cmd] += 1
            if source not in self.sources:
                self.sources[source] = 0
            self.sources[source] += 1
            if target not in self.targets:
                self.targets[target] = 0
            self.targets[target] += 1
            #self.ipsearch(c,e)
            if cmd in ["privmsg", "pubmsg", "notice", "privnotice"]:
                self.analyzeMsg(c, e)
            
    def printSummary(self):
##        import pdb
##        pdb.set_trace()                                 
        if not (self.cmds or self.sources or self.targets):  
            self.doOutput("\tNo IRC seen\n")
            return
        self.doOutput("\nCommand counts:\n\n")
        for k,v in orderByValue(self.cmds, limit=self.limit):
            self.doOutput("\t%s %d\n" % (k, v))
        self.doOutput("\nSource counts:\n\n")
        for k,v in orderByValue(self.sources, limit=self.limit):
            self.doOutput("\t%s  %d\n" % (k, v))
        self.doOutput("\nTarget counts:\n\n")
        for k,v in orderByValue(self.targets, limit=self.limit):
            self.doOutput("\t%s  %d\n" % (k, v))
        self.doOutput("\nDetailed report for IRC keyword matches:\n\n")
        self.doOutput("\tRepeated Lines %d\n" % len(self.lines))
        self.doOutput("\tIPs %d\n" % len(self.ips))
        self.doOutput("\tUsers %d\n" % len(self.users))
        self.doOutput("\tChannels %d\n" % len(self.channels))
        if len(self.wordlines) > 0:
            self.doOutput("\tLines matching wordlist:\n")
            for line, matches in self.wordlines:
                self.doOutput("\t\t%s\n\t\t\t(matches %s)\n" % (line, matches))
        if len(self.botlines) > 0:
            self.doOutput("\n\tPossible bot commands:\n")
            for line, matches in self.botlines:
                self.doOutput("\t\t%s\n\t\t\t(matches %s)" % (line, matches))
        """
        print "\n****** talking ips ******"
        for k,v in self.ips.items():
            print str(k) + ":"
            for i in v.keys():
                print "\t"+i
        """

    
    def ipsearch(self, c, e):
        cmd = e.eventtype()
        if cmd in ['privmsg', 'mode', 'quit', 'nick', 'join', 'pubmsg']:
            #srcip = dnet.addr(c.pkt.src)
            srcip = e.src
            if srcip not in self.ips:
                self.ips[srcip] = {}
            if e.source() is not None:
                self.ips[srcip][e.source()] = 1
                
    def botcmds(self, c, e):   
        """Find lines matching botwords"""
        data = ' '.join(e.arguments())
        matches = [w for w in self.botwords if w in data]
        if len(matches) > 0:  
            self.botlines.append( [str(e), matches])
        
    def keywords(self, c, e):
        """Find lines matching word list"""
        data = ' '.join(e.arguments())
        matches = [w for w in self.words if w in data]
        if len(matches) > 0: 
            self.wordlines.append([str(e), matches])
    
    def analyzeMsg(self, c, e):
        """
        arguments:
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        This function handles analysis for any IRC events.
        """
        channel = None
        targetuser = None
        fromuser = None
        if e.source() == None:
            return
        else:
            fromuser = e.source()
        #t = time.asctime(time.localtime(c.ts))
        t = e.time
        cmd = e.eventtype()
        if cmd == "pubmsg" or cmd=="notice":
            channel = e.target()
        if cmd == "privmsg" or cmd=="privnotice":
            targetuser = e.target()
        srcip = e.src
        dstip = e.dst
        rest = " ".join(e.arguments())
        # track channels
        if channel is not None:
            self.channels.setdefault(channel, 0)
            self.channels[channel] += 1
        # track talkers
        self.users.setdefault(fromuser, 0)
        self.users[fromuser] += 1
        # track ip addrs
        self.ips.setdefault(srcip, 0)
        self.ips[srcip] += 1
        self.ips.setdefault(dstip, 0)
        self.ips[dstip]+=1
        # track repeating lines
        self.lines.setdefault(rest, 0)
        self.lines[rest] += 1
        # search for keywords
        self.keywords(c, e)
        self.botcmds(c, e)
        
        
        
        
        
