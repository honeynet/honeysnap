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
import socket
import sys
import re
#import dnet
from util import orderByValue, make_dir
from base import Base

# global bot word list.
botprefixes = ["", "?", ":", ".", "-", "!", "\`",  "\\", "|"]
botcoms = ["die ", "esay ", "flood ", "m ", "me ", "part ", "payment ", "ping ", "pingstop ", "s ", "say ", "server ", "services ", "startflood ",
        "stopflood ", "x ", "advscan ", "asc ", "aolspam.", "antiaction ", "antibold ", "anticolour ", "antinotice ", "antipub ", "antirepeat ", "antireverse ",
        "antiunderline ", "antiurl ", "autovoice ", "carnivore ", "chanserv ", "clone ", "c ", "clonestop ", "cycle ", "c_raw ", "c_mode ", "c_nick ",
        "c_join ", "c_part ", "c_privmsg ", "c_action ", "c_r ", "c_m ", "c_n ", "c_j ", "c_p ", "c_pm ", "c_a ", "cvar.", "download ", "dl ", "dynamicexempts ",
        "dynamicinvites ", "ddos.", "enforcetopiclimit ", "email ", "execute ", "findfile ", "ff ", "findfilestopp ", "http.", "icmp ", "icmpflood ",
        "nodesynch ", "locked ", "noop ", "op ", "passive ", "private ", "rename ", "mv ", "revenge ", "revengebot ", "scanall ", "sa ", "scandel ", "scan.",
        "scanstop ", "scanstats ", "secret ", "seen ", "seen ", "shared ", "sniffer.", "stats ", "spam.", "syn ", "synstop ", "strictop ", "suspended ", "topic ",
        "udp ", "udpstop ", "update ", "up ", "userexempts ", "userinvites ", "voice "]

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

    def __init__(self, hp):        
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
        self.currenttopicsBotCmd = []
        self.currenttopicsKeyword = []
        self.serversvisited = []
        self.channelsvisited = []
        self.possbotnet = False
        self.honeypot = hp       
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
            self.fp.write("%s\t%s:%s -> %s:%s\t%s\t%s\t%s\t%s" % (self.tf(e.time), e.src, e.sport, e.dst, e.dport,
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
            self.fp = open(self.dir + "/%s" % filename, "a")  
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
            if cmd in ['privmsg', 'mode', 'quit', 'nick', 'join', 'pubmsg', 'currenttopic', 'topicinfo', 'topic', 'pass']:
                self.analyzeMsg(c, e)
            
    def printSummary(self):
        """Print a summary of interesting IRC lines"""
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
                self.doOutput("\t\t%s\t[Honeysnap: line matches %s]\n" % (line, matches))
        if len(self.botlines) > 0:
            self.doOutput("\n\tPossible bot commands:\n")
            for line, matches in self.botlines:
                self.doOutput("\t\t%s\t([Honeysnap: line matches %s]\n" % (line, matches))
            if len(self.serversvisited) > 0:
                self.possbotnet = self.possbotnetMatch()
            if self.possbotnet:
                connections = ""
                for server, port, password in self.serversvisited:
                    if server != self.honeypot:
                        try:
                            host = socket.gethostbyaddr(server)[0]
                        except socket.herror:
                            host = server
                        connections = "\t\tServer: %s\tPort: %s\tPassword: %s\t" % (host, port, password)
                        for conn, channel, passwd in self.channelsvisited:
                            if conn == server:
                                tmp = "[Channel: %s Password: %s]\t" % (channel, passwd)
                                connections += tmp
                if len(connections) > 0:
                    self.doOutput("\n\tPossible botnet command and control servers and channels:\n")
                    self.doOutput(connections + "\n\n")
        """
        print "\n****** talking ips ******"
        for k,v in self.ips.items():
            print str(k) + ":"
            for i in v.keys():
                print "\t"+i
        """
        
    def possbotnetMatch(self):
        """ 
        Look for matching hosts in self.wordlines
        and self.botlines to find possible botnet servers
        stored in self.serversvisited
        """
        mergedlist = self.wordlines
        for s in self.botlines:
            mergedlist.append(s)
            
        for server, port, password in self.serversvisited:
            for line, matches in mergedlist:
                if server in line:
                    return True
        return False
    
    def ipsearch(self, c, e):
        cmd = e.eventtype()
        if cmd in ['privmsg', 'mode', 'quit', 'nick', 'join', 'pubmsg', 'currenttopic', 'topicinfo', 'topic', 'pass']:
            #srcip = dnet.addr(c.pkt.src)
            srcip = e.src
            if srcip not in self.ips:
                self.ips[srcip] = {}
            if e.source() is not None:
                self.ips[srcip][e.source()] = 1
                
    def botcmds(self, c, e):   
        """Find lines matching botwords"""     
        if e.eventtype() == 'topicinfo':
            self.topics(e, 'botcmds')
            return
        data = ' '.join(e.arguments())
        matches = [w for w in self.botwords if w in data]
        if len(matches) > 0:  
            self.botlines.append([str(e), matches])  
            if e.eventtype() == 'currenttopic':
                self.currenttopicsBotCmd.append(str(e))
        
    def keywords(self, c, e):
        """Find lines matching word list"""    
        if e.eventtype() == 'topicinfo':
            self.topics(e, 'keyword')
            return        
        data = ' '.join(e.arguments())
        matches = [w for w in self.words if w in data]
        if len(matches) > 0: 
            self.wordlines.append([str(e), matches])  
            if e.eventtype() == 'currenttopic':
                self.currenttopicsKeyword.append(str(e))            

    def topics(self, e, matchtype):
        """
        Find matching currenttopic and topicinfo
        Store result in self.botlines or self.wordlines (for keyword matches)
        """
        savedtopics = self.currenttopicsBotCmd
        matchlist   = self.botlines
        if matchtype == 'keyword':
            savedtopics = self.currenttopicsKeyword
            matchlist   = self.wordlines
        timecmp = str(e).split(' ')[0].strip()
        for s in savedtopics:
            if s.split(' ')[0].strip() == timecmp:
                if not str(e) in matchlist:
                    matchlist.append([str(e), 'currenttopic'])
                    break
    
    def analyzeMsg(self, c, e):
        """
        arguments:
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        This function handles analysis for any IRC events.
        """
        
        if e.eventtype() == 'pass':
            sep = str(e).split(' ')
            port = sep[len(sep) - 1].split('\t')[0].split(':')[1]
            self.serversvisited.append([e.dst, port, e.target()])
            return
            
        if e.eventtype() == 'join':
            foundmatch = False
            for server, port, passwd in self.serversvisited:
                if e.dst in server:
                    foundmatch = True
            if not foundmatch:
                sep = str(e).split(' ')
                port = sep[len(sep) - 1].split('\t')[0].split(':')[1]
                self.serversvisited.append([e.dst, port, ""])
            self.channelsvisited.append([e.dst, e.target(), " ".join(e.arguments())])
            return
            
        channel = None
        targetuser = None
        fromuser = None
        if e.source() == None:
            return
        else:
            fromuser = e.source()
        t = e.time
        cmd = e.eventtype()
        if cmd == "pubmsg" or cmd=="notice" or cmd=="topic":
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
        
        
        
        
        
