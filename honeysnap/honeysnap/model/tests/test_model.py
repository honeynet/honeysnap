#!/usr/bin/env python
# encoding: utf-8
################################################################################
#   (c) 2007 The Honeynet Project
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
from datetime import datetime
from nose.tools import raises
from sqlalchemy.exceptions import SQLError

from honeysnap.importers.sebekDecode import SBK_READ, SBK_WRITE, SBK_SOCK, SBK_OPEN 
from honeysnap.model.model import * 
            
class test_model(unittest.TestCase):   
    """Test some very basic properties of the model"""
    
    def setUp(self):                 
        self.engine = connect_to_db('sqlite:///')  
        self.session = create_session()
        ipid = Ip.id_get_or_create("192.168.0.1")
        h = Honeypot(name="ukad01", ip_id=ipid, state="Up", description="A honeypot")
        self.session.save(h) 
        self.session.flush()
        src = Ip(ip_addr="10.0.0.1")
        dst = Ip(ip_addr="254.168.0.2")                         
        self.session.save(src)
        self.session.save(dst) 
        self.session.flush()
        f = Flow(src_id=src.id, sport=80, packets=3, bytes=56, dst_id=dst.id, 
            dport=45678, starttime=datetime(2007, 01, 01, 0, 0, 0, 0), 
            lastseen=datetime(2007, 01, 02, 0, 0, 0, 0))
        self.session.save(f)
        h.flows.append(f)   
        sebek = Sebek(version=3, type=SBK_READ, timestamp=datetime(2007, 01, 01, 0, 0, 0, 0), 
                pid=23, fd=23, uid=0, command='ssh', parent_pid=1, inode=34324, data='uname -a')
        h.sebek_lines.append(sebek)
        self.session.flush()
        
    def tearDown(self): 
        Ip.id_cache = {}
        self.session.clear() 
        metadata.drop_all()
         
    def test_by_ip(self):                       
        """get Honeypot by Ip"""
        h = Honeypot.by_ip(self.session, "192.168.0.1")
        assert h.name == "ukad01"        

    def test_get_or_create(self):                        
        """get_or_create() should get or create"""
        h = Honeypot.get_or_create(self.session, "192.168.0.1")
        assert h.name == "ukad01"
        h = Honeypot.get_or_create(self.session, "192.168.0.2")
        assert h.name == "HS_Fake"

    @raises(ValueError)
    def test_ip_init(self):
        """__init__ should raise ValueError with bad key"""
        i = Ip(ipaddr="1.2.3.4")  
        
    @raises(ValueError)
    def test_honeypot_init(self):
        """__init__ should raise ValueError with bad key"""
        h = Honeypot(name = "fred", george="bill") 
        
    @raises(ValueError)
    def test_flow_init(self):
        """__init__ should raise ValueError with bad key"""
        f = Flow(src_id=1, sport=80, packets=3, bytes=56, dst_id=2,
            dport=45678, starttime=datetime(2007, 01, 01, 0, 0, 0, 0), 
            last_seen=datetime(2007, 01, 02, 0, 0, 0, 0))

    def test_flow_icmp(self):
        """flow should create with icmp_type and icmp_code"""
        f = Flow(honeypot_id=1, ip_proto=1, src_id=1, packets=3, bytes=56, dst_id=2, icmp_code=1, icmp_type=2,
            starttime=datetime(2007, 01, 01, 0, 0, 0, 23), lastseen=datetime(2007, 01, 02, 0, 0, 0, 0))
        assert f.icmp_code == 1
        assert f.icmp_type == 2
        assert f.dport == 1
        assert f.sport == 2 
        print str(f)    
        assert str(f) == "[honeypot: 1, ip_proto: 1, src: 1, dst: 2, type: 2, code: 1, packets: 3, bytes: 56, starttime: 2007-01-01 00:00:00.000023, lastseen: 2007-01-02 00:00:00, filename: None]"
            
    @raises(ValueError)            
    def test_sebek_init(self):
        """__init__ should raises ValueError with bad key"""
        sebek = Sebek(version=3, type=0, starttime=datetime.now(), pid=23, fd=23, uid=0, command='ssh', parent_pid=1, inode=34324, data='uname -a')

    @raises(SQLError)
    def test_sebek_dup(self):
        """should raise exception on duplicate sebek records"""  
        h = Honeypot.by_ip(self.session, "192.168.0.1") 
        sebek = Sebek(version=3, type=SBK_READ, timestamp=datetime(2007, 01, 01, 0, 0, 0, 0), pid=23, 
                fd=23, uid=0, command='ssh', parent_pid=1, inode=34324, data='uname -a')
        h.sebek_lines.append(sebek)
        self.session.flush()        
        
    @raises(SQLError)
    def test_hp_unique(self):               
        """Should raise exception with duplicate ip addrs"""
        ipid = Ip.id_get_or_create("192.168.0.1")
        h = Honeypot(name="test", ip_id=ipid, state="Up")   
        self.session.save(h)
        self.session.flush()               
        
    def test_id_get_or_create(self): 
        """id_get_or_create should return valid id and create if needed"""
        ipid = Ip.id_get_or_create("192.168.0.1")
        assert ipid == 1                                      
        ipid = Ip.id_get_or_create("1.2.3.4")
        assert type(ipid) == type(1)
        assert ipid != 1
        ipid2 = Ip.id_get_or_create("1.2.3.4")
        assert ipid == ipid2
         
    def test_id_get_or_create_delete(self):
        """id_get_or_create should do the right thing if an object has been deleted"""
        ipid1 = Ip.id_get_or_create("192.168.0.1")
        ipid2 = Ip.id_get_or_create("192.168.0.2")
        ipid3 = Ip.id_get_or_create("192.168.0.3")
        ip = self.session.query(Ip).get_by(id=ipid1)
        self.session.delete(ip)
        self.session.flush()
        ipid4 = Ip.id_get_or_create("192.168.0.4")
        ipid5 = Ip.id_get_or_create("192.168.0.1")
        assert ipid5 != ipid1
        
    def test_num_of_type(self):    
        """num of type should correctly query sebek table""" 
        print self.session.query(Honeypot).select()[0]
        h = Honeypot.by_ip(self.session, "192.168.0.1")         
        n = Sebek.num_of_type(self.session, h, SBK_READ)     
        assert n == 1 
        n = Sebek.num_of_type(self.session, h, SBK_WRITE)                                         
        assert n == 0 
        n = Sebek.num_of_type(self.session, h, SBK_READ, starttime=datetime(2006, 01, 01, 0, 0, 0, 0), 
            endtime=datetime(2007, 02, 01, 0, 0, 0, 0))           
        assert n == 1       
        n = Sebek.num_of_type(self.session, h, SBK_READ, starttime=datetime(2006, 01, 01, 0, 0, 0, 0), 
            endtime=datetime(2006, 02, 01, 0, 0, 0, 0))           
        assert n == 0

    def test_get_lines(self): 
        """get_lines should correctly query sebek table"""
        h = Honeypot.by_ip(self.session, "192.168.0.1")   
        lines = Sebek.get_lines(self.session, h, SBK_READ, starttime=datetime(2006, 01, 01, 0, 0, 0, 0), 
                endtime=datetime(2007, 02, 01, 0, 0, 0, 0))     
        assert type(lines[0]) == type(Sebek())
        assert lines[0].command == 'ssh'
        assert len(lines) == 1 
        lines = Sebek.get_lines(self.session, h, SBK_WRITE, starttime=datetime(2006, 01, 01, 0, 0, 0, 0), 
                endtime=datetime(2007, 02, 01, 0, 0, 0, 0))                                         
        assert len(lines) == 0
        lines = Sebek.get_lines(self.session, h, SBK_READ, starttime=datetime(2006, 01, 01, 0, 0, 0, 0), 
                endtime=datetime(2007, 02, 01, 0, 0, 0, 0))           
        assert type(lines[0]) == type(Sebek())
        assert lines[0].command == 'ssh'
        assert len(lines) == 1
        lines = Sebek.get_lines(self.session, h, SBK_READ, starttime=datetime(2006, 01, 01, 0, 0, 0, 0), 
                endtime=datetime(2006, 02, 01, 0, 0, 0, 0), excludes=['ssh'])           
        assert len(lines) == 0
    
    @raises(ValueError)
    def test_create_bad_ip_talker(self):
        """IRCTalker.__init__ should raise an exception with bad argument"""
        t = IRCTalker(names='fred') 
        
    def test_create_irc_talker(self):
        """IRCTalker __init__ should work"""
        t = IRCTalker(name='fred!george@localhost')   
        assert t.name=='fred!george@localhost'
        assert str(t) == '[name: fred!george@localhost]' 
        assert t.nick == 'fred'  
        assert t.user == 'george'
        assert t.host == 'localhost'
  
    def test_irc_id_get_or_create(self): 
        """IRCTalker.id_get_or_create should return valid id and create if needed"""
        ipid = IRCTalker.id_get_or_create("fred!fred@localhost")
        assert ipid == 1                                      
        ipid = Ip.id_get_or_create("george!george@dsf.com")
        assert type(ipid) == type(1)
        assert ipid != 1
        ipid2 = Ip.id_get_or_create("george!george@dsf.com")
        assert ipid == ipid2

    def test_irc_id_get_or_create_delete(self):
        """IRCTalker.id_get_or_create should do the right thing if an object has been deleted"""
        ipid1 = IRCTalker.id_get_or_create("me@me.com")
        ipid2 = IRCTalker.id_get_or_create("fred!fred@fred.com")
        ipid3 = IRCTalker.id_get_or_create("l33t@hacker")
        ip = self.session.query(Ip).get_by(id=ipid1)
        self.session.delete(ip)
        self.session.flush()
        ipid4 = Ip.id_get_or_create("31337!mum@aol.com")
        ipid5 = Ip.id_get_or_create("me@me.com")
        assert ipid5 != ipid1  

    @raises(ValueError)   
    def test_create_bad_irc_messsage(self):
        """IRCTalker.__init__ should raise an exception with bad argument"""
        m = IRCMessage(fred='fred')
        
    def test_create_irc_message(self):
        """should be able to create an IRC message"""
        h = Honeypot.by_ip(self.session, "192.168.0.1") 
        ircsrc = IRCTalker(name='fred')
        ircdst = IRCTalker(name='george') 
        src_id = Ip.id_get_or_create("192.168.0.2")
        dst_id = Ip.id_get_or_create("192.168.0.3") 
        m = IRCMessage(src_id=src_id, dst_id=dst_id, sport=4432, dport=6667, 
            command='PRIVMSG', timestamp=datetime.now(), text='hi there')          
        print m
        m.irc_from=ircsrc
        m.irc_to=ircdst    
        h.irc_messages.append(m) 
        self.session.flush()  
        
    def test_channel(self):
        """if dst starts with a '#', channel should exist"""
        h = Honeypot.by_ip(self.session, "192.168.0.1") 
        ircsrc = IRCTalker(name='fred')
        ircdst = IRCTalker(name='#secret') 
        src_id = Ip.id_get_or_create("192.168.0.2")
        dst_id = Ip.id_get_or_create("192.168.0.3") 
        m = IRCMessage(src_id=src_id, dst_id=dst_id, sport=4432, dport=6667, 
            command='PRIVMSG', timestamp=datetime.now(), text='hi there')          
        m.irc_from=ircsrc
        m.irc_to=ircdst 
        h.irc_messages.append(m)               
        self.session.flush()
        assert m.channel == '#secret'    
        
    def test_save_table(self):
        """save_table should save a list to a table"""  
        s1 = dict(honeypot_id=1, version=3, type=SBK_READ, timestamp=datetime(2007, 01, 01, 0, 0, 1, 0), 
                pid=23, fd=23, uid=0, command='ssh', parent_pid=1, inode=34324, data='uname -al')    
        s2 = dict(honeypot_id=1, version=3, type=SBK_READ, timestamp=datetime(2007, 01, 01, 0, 0, 2, 0), 
                pid=23, fd=23, uid=0, command='ssh', parent_pid=1, inode=34324, data='hello world')
        for i in [1,2]:
            save_table(sebek_table, [s1, s2])                                        
            assert self.session.query(Sebek).count() == 3
        
        
if __name__ == '__main__':
    unittest.main()