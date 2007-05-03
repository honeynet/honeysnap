################################################################################
# (c) 2006, The Honeynet Project
#   Author: Arthur Clune arthur@honeynet.org.uk
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

import unittest
from honeysnap.model.model import *
from honeysnap.importers.ircDecode import * 
from honeysnap.importers.hsIRC import HnyEvent

from honeysnap.singletonmixin import HoneysnapSingleton                                                             

class test_ircDecode(unittest.TestCase):
    def setUp(self):
        singleton = HoneysnapSingleton.getInstance({ 'dburi' : 'sqlite:///', 'debug' : False, 'irc_ports' : { '192.168.0.1' : []} })
        self.ircd = IrcDecode(None, 'testing', '192.168.0.1')
        self.ircd.port = 6667
        
    def tearDown(self):   
        HoneysnapSingleton._forgetClassInstanceReferenceForTesting()        
        self.ircd.session.clear() 
        metadata.drop_all()        

    def test_raw_message(self):
       """shouldn't store messages of type all_raw_messages in db"""
       assert self.ircd.count == 0
       cmd = 'all_raw_messages'
       srcid = IRCTalker.id_get_or_create('fred!fred@localhost')
       dstid = IRCTalker.id_get_or_create('george!zzz@dsfdf.sdfd.com')   
       pkt = dpkt.ip.IP()
       pkt.src = inet_aton('192.168.0.1')
       pkt.dst = inet_aton('192.168.0.2')
       pkt.data = dpkt.tcp.TCP()
       pkt.data.dport = 234
       pkt.data.sport = 6667
       src = 'fred!fred@localhost'
       dst = 'george!zzz@dsfdf.sdfd.com'
       e  = HnyEvent(1111.0, pkt, cmd, src, dst, '')
       self.ircd.decode('', e)
       assert self.ircd.count == 0
       assert len(self.ircd.insert_list) == 0
       
    def test_max_data_size(self):
       """should restict max data size (ie not raise SQLError)"""  
       text = ''.join( 'a' for x in xrange(0,MAX_IRC_TEXT_SIZE+5))
       srcid = IRCTalker.id_get_or_create('fred!fred@localhost')
       dstid = IRCTalker.id_get_or_create('george!zzz@dsfdf.sdfd.com')   
       pkt = dpkt.ip.IP()
       pkt.src = inet_aton('192.168.0.1')
       pkt.dst = inet_aton('192.168.0.2')
       pkt.data = dpkt.tcp.TCP()
       pkt.data.dport = 234
       pkt.data.sport = 6667
       src = 'fred!fred@localhost'
       dst = 'george!zzz@dsfdf.sdfd.com'
       e  = HnyEvent(1111.0, pkt, 'privmsg', src, dst, text)
       self.ircd.decode('', e)
       self.ircd.write_db()
       
    def test_max_command_size(self):
       """shold restrict max command size (ie not raise SQLError)"""
       cmd = ''.join( 'a' for x in xrange(0,MAX_IRC_COMMAND_SIZE+5))
       srcid = IRCTalker.id_get_or_create('fred!fred@localhost')
       dstid = IRCTalker.id_get_or_create('george!zzz@dsfdf.sdfd.com')   
       pkt = dpkt.ip.IP()
       pkt.src = inet_aton('192.168.0.1')
       pkt.dst = inet_aton('192.168.0.2')
       pkt.data = dpkt.tcp.TCP()
       pkt.data.dport = 234
       pkt.data.sport = 6667
       src = 'fred!fred@localhost'
       dst = 'george!zzz@dsfdf.sdfd.com'
       e  = HnyEvent(1111.0, pkt, cmd, src, dst, '')
       self.ircd.decode('', e)
       self.ircd.write_db()       
       
    def test_dup_lines(self):
       """shouldn't try and store dup lines in insert_list""" 
       cmd = 'privmsg'
       srcid = IRCTalker.id_get_or_create('fred!fred@localhost')
       dstid = IRCTalker.id_get_or_create('george!zzz@dsfdf.sdfd.com')   
       pkt = dpkt.ip.IP()
       pkt.src = inet_aton('192.168.0.1')
       pkt.dst = inet_aton('192.168.0.2')
       pkt.data = dpkt.tcp.TCP()
       pkt.data.dport = 234
       pkt.data.sport = 6667
       src = 'fred!fred@localhost'
       dst = 'george!zzz@dsfdf.sdfd.com'
       for i in xrange(1,5):
           e  = HnyEvent(1111.0, pkt, cmd, src, dst, '')
           self.ircd.decode('', e)
           assert len(self.ircd.insert_list) == 1   
                                        
    def test_already_in_db(self):
       """should spot lines already in db and skip"""
       ircmq = self.ircd.session.query(IRCMessage)
       cmd = 'privmsg'
       srcid = IRCTalker.id_get_or_create('fred!fred@localhost')
       dstid = IRCTalker.id_get_or_create('george!zzz@dsfdf.sdfd.com')   
       pkt = dpkt.ip.IP()
       pkt.src = inet_aton('192.168.0.1')
       pkt.dst = inet_aton('192.168.0.2')
       pkt.data = dpkt.tcp.TCP()
       pkt.data.dport = 234
       pkt.data.sport = 6667
       src = 'fred!fred@localhost'
       dst = 'george!zzz@dsfdf.sdfd.com'
       e  = HnyEvent(1111.0, pkt, cmd, src, dst, '')
       self.ircd.decode('', e)
       self.ircd.write_db()       
       assert ircmq.count() == 1
       e  = HnyEvent(1111.0, pkt, cmd, src, dst, '')
       self.ircd.decode('', e)
       self.ircd.write_db()     
       assert ircmq.count() == 1  
       
    def test_empty_insert_list(self):
       """shouldn't try and write to db if insert_list is emptry"""
       self.ircd.insert_list = []                                  
       # insert_many would barf if we passed it an empty list so this is a valid test
       self.ircd.write_db()

    
if __name__ == '__main__':
    unittest.main()