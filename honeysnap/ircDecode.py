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
from hsIRC import HoneySnapIRC
import math
import time
import re
import dnet
from operator import itemgetter

botprefixes = [".", "-", "!", "\`",  "\\", "|"]
botcoms = ["die", "esay", "flood", "m", "me", "part", "payment", "ping", "s", "say", "server",
        "services", "startflood", "stopflood", "x", "antiaction", "antibold", "anticolour", "antinotice",
        "antipub", "antirepeat", "antireverse", "antiunderline", "antiurl", "autovoice", "chanserv", 
        "cycle", "dynamicexempts", "dynamicinvites", "enforcetopiclimit", "nodesynch", "locked",
        "noop", "op", "passive", "private", "revenge", "revengebot", "secret", "seen", "seen",
        "shared", "stats", "strictop", "suspended", "topic", "userexempts", "userinvites", "voice"]

botwords = []
for i in botprefixes:
    tmp = [i+w for w in botcoms]
    botwords += tmp
botwords = set(botwords)

    
class ircDecode(object):
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
        self.cmds = {}
        self.sources = {}
        self.targets = {}
        self.ips = {}
        self.users = {}
        self.channels = {}
        self.repeats = {}
        self.lines = {}
        self.botlines = {}
        self.privcount = 0
        
    def decodeCB(self, c, e):
        """
        Callback to register with HoneySnapIRC
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        """
        if e.eventtype() not in ['ping', 'pong'] and e.eventtype() != 'all_raw_messages':
##            print "%s\t%s\t%s\t%s\t%s" % (long(math.ceil(time.time())),
##                                          e.eventtype(), e.source(),
##                                          e.target(), ' '.join(e.arguments()))
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
            if cmd in ["privmsg", "pubmsg"]:
                self.analyzePrivmsg(c, e)
            
    def printSummary(self):
        print "\n****** command count *******"
        for k,v in self.cmds.items():
            print "%s: %d" % (k, v)
        print "\n****** source count *******"
        for k,v in self.sources.items():
            print "%s : %d" % (k, v)
        print "\n****** target count ******"
        for k,v in self.targets.items():
            print "%s : %d" % (k, v)
        print "Detailed report for IRC keyword matches:"
        print "\tRepeated Lines %d" % len(self.lines)
        print "\tIPs %d" % len(self.ips)
        print "\tUsers %d" % len(self.users)
        print "\tChannels %d" % len(self.channels)
        if len(self.botlines) > 0:
            print "\tPossible bot commands:"
            vals = self._orderByValue(self.botlines)
            for i in vals:
                print "\t\t%s => %d" % i
            
        """
        print "\n****** talking ips ******"
        for k,v in self.ips.items():
            print str(k) + ":"
            for i in v.keys():
                print "\t"+i
        """
    def _orderByValue(self, d):
        return sorted(d.iteritems(), key=itemgetter(1), reverse=True)
    
    def ipsearch(self, c, e):
        cmd = e.eventtype()
        if cmd in ['privmsg', 'mode', 'quit', 'nick', 'join', 'pubmsg']:
            srcip = dnet.addr(c.pkt.src)
            #srcip = e.src
            if srcip not in self.ips:
                self.ips[srcip] = {}
            if e.source() is not None:
                self.ips[srcip][e.source()] = 1
                
    def botcmds(self, c, e):
        data = ' '.join(e.arguments())
        matches = [w for w in botwords if w in data]
        if len(matches) > 0:
            self.botlines.setdefault(data, 0)
            self.botlines[data] += 1
        return matches
        
    def keywords(self, c, e):
        pass
    
    def analyzePrivmsg(self, c, e):
        """
        arguments:
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        This function handles privmsg analysis for any privmsg events.
        """
        channel = None
        targetuser = None
        fromuser = None
        if e.source() == None:
            return
        else:
            fromuser = e.source()
        t = time.asctime(time.localtime(c.ts))
        #t = e.time
        cmd = e.eventtype()
        if cmd == "pubmsg":
            channel = e.target()
        if cmd == "privmsg":
            targetuser = e.target()
        srcip = dnet.addr(c.pkt.src)
        dstip = dnet.addr(c.pkt.dst)
        #srcip = e.src
        #dstip = e.dst
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
        # XXX TODO
        # Move this functionality here from main
        self.keywords(c, e)
        self.botcmds(c, e)
        
        
        
        
        
