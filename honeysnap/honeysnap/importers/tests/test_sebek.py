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
from nose.tools import raises 
from sqlalchemy import *

from honeysnap.importers.sebekDecode import *
from honeysnap.model.model import *

class test_sebek_decode(unittest.TestCase):   
    """Test sebek decoding"""
    
    def setUp(self): 
        self.engine = connect_to_db('sqlite:///')
        # this is very nasty....           
        # don't want to run __init__ as don't have options or a file 
        SebekDecode.__init__ = lambda self: None
        self.sbd = SebekDecode()  
        self.sbd.log = {}                 
        self.session = create_session()  
        self.sbq = self.session.query(Sebek)  
        self.sbd.hash = {}
        self.sbd.insert_list = []
        self.sbd.hp = Honeypot.get_or_create(self.session, '192.168.0.1')   
        self.session.flush()
         
    def tearDown(self):
        self.session.clear() 
        metadata.drop_all()
        
    def test_sbk_write(self): 
        """sbk_write should add line to db"""
        self.sbd.sbk_write(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="/dev/fred", parent_pid=1, inode=12341)   
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1
        assert data[0].inode==12341
        
    @raises(SebekDecodeError)
    def test_bad_write(self):
        """sbk_write should fail for version 1 data"""
        self.sbd.sbk_write(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data="/dev/fred", parent_pid=1, inode=12345)   

    def test_sbk_sock(self): 
        """sbk_sock should add line to db"""
        self.sbd.sbk_write(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="/dev/fred", parent_pid=1, inode=12342)   
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].inode==12342        

    @raises(SebekDecodeError)
    def test_bad_sock(self):    
        """sbk_sock should fail for version 1 data"""
        self.sbd.sbk_sock(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data="/dev/fred", parent_pid=1, inode=12345)        

    def test_sock_open(self):  
        """sbk_open should add line to db"""        
        self.sbd.sbk_open(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="/dev/fred", parent_pid=1, inode=12343)  
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].inode==12343
        
    @raises(SebekDecodeError)
    def test_bad_open(self):  
        """sbk_open should fail for version 1 data"""        
        self.sbd.sbk_open(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data="/dev/fred", parent_pid=1, inode=12345)    

    @raises(SebekDecodeError)
    def test_sbk_keystrokes_bad_ppid(self):
        """sbk_keystrokes raise error if parent_pid given in v1 data"""
        self.sbd.sbk_keystrokes(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan", parent_pid=1) 

    @raises(SebekDecodeError)
    def test_sbk_keystrokes_bad_ppid(self):
        """sbk_keystrokes raise error if parent_pid given in v1 data"""
        self.sbd.sbk_keystrokes(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan", inode=1)

    def test_sbk_keystrokes(self):
        """sbk_keystrokes should add line to db and handle multiple lines correctly"""
        self.sbd.sbk_keystrokes(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan")
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==0
        self.sbd.sbk_keystrokes(version=1, t=12345, pid=1, fd=1, uid=1, com="sh", data=" 192.168.0.1\n")        
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].data=="./scan 192.168.0.1"   

    def test_sbk_keystrokes_v3(self):
        """sbk_keystrokes should add v3 lines to db and handle multiple lines correctly"""
        self.sbd.sbk_keystrokes(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan", parent_pid=1, inode=12345)
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==0               
        self.sbd.sbk_keystrokes(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data=" 192.168.0.1\n", parent_pid=1, inode=12345)        
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].data=="./scan 192.168.0.1" 
        
    def test_sbk_keystrokes_pid(self):
        """sbk_keystrokes should not combine lines with different pids"""  
        self.sbd.sbk_keystrokes(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan", parent_pid=1, inode=12345)
        self.sbd.sbk_keystrokes(version=3, t=12345, pid=2, fd=1, uid=1, com="sh", data=" 192.168.0.1", parent_pid=1, inode=12345)        
        self.sbd.sbk_keystrokes(version=3, t=12345, pid=2, fd=1, uid=1, com="sh", data="\n", parent_pid=1, inode=12345)          
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1
        assert data[0].data==" 192.168.0.1"
    
    @raises(SebekDecodeError)    
    def test_unpack_bad_ver(self):
        """unpack should fail on unknown version number"""
        buf = '\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10scan'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)

    @raises(SebekDecodeError)
    def test_unpack_short(self):
        """unpack should fail with short data""" 
        buf = '\x00\x00\x0c'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)  
        
    def test_unpack_ver1_keystroke(self):
        """should unpack ver1 keystroke data"""
        buf = '\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10scan'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)
        print magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest
        assert version == 1  
        assert type == SBK_READ                 
        assert rest == 'scan'
        assert com.startswith('bash')
        assert t == 12345
 
    def test_unpack_ver2_keystroke(self):
        """should unpack ver2 keystroke data"""
        buf = '\x00\x00\x00\x01\x00\x03\x00\x00\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10scan'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)
        print magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest
        assert version == 3 
        assert type == SBK_READ                 
        assert rest == 'scan'
        assert com.startswith('bash')
        assert t == 12345
        assert parent_pid == 1
        assert inode == 23

    def test_unpack_ver2_sock(self):
        """should unpack ver2 sock data"""        
        buf = '\x00\x00\x00\x01\x00\x03\x00\x02\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08sock'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)  
        assert version == 3 
        assert type == SBK_SOCK                  
        assert rest == 'sock'
        assert com.startswith('bash')
        assert t == 12345
        assert parent_pid == 1
        assert inode == 23

    def test_unpack_ver2_write(self):
        """should unpack ver2 write data"""
        buf = '\x00\x00\x00\x01\x00\x03\x00\x01\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08/dev/null'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)  
        assert version == 3  
        assert type == SBK_WRITE                
        assert rest == '/dev/null'
        assert com.startswith('bash')
        assert t == 12345
        assert parent_pid == 1
        assert inode == 23

    def test_unpack_ver2_open(self):
        """should unpack ver2 open data"""  
        buf = '\x00\x00\x00\x01\x00\x03\x00\x03\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08/dev/null'
        magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.sbd.unpack_sebek(buf)  
        assert version == 3  
        assert type == SBK_OPEN                
        assert rest == '/dev/null'
        assert com.startswith('bash')
        assert t == 12345
        assert parent_pid == 1
        assert inode == 23     

    def test_packet_handler_bad(self):
        """packet_handler should fail silently with bad data"""
        buf = 'this\x22\x00\x22isapileofstuff'
        self.sbd.packet_handler(12345, buf)  
        assert len(self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id))==0

    def test_packet_handler_read(self):  
        """packet_handler should store read data"""
        buf = '\x00\x00\x00\x01\x00\x03\x00\x00\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10scan\n'
        self.sbd.packet_handler(12345, buf)  
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].type == SBK_READ

    def test_packet_handler_write(self):
        """packet_handler should store SBK_WRITE data"""  
        buf = '\x00\x00\x00\x01\x00\x03\x00\x01\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08/dev/null'
        self.sbd.packet_handler(12345, buf) 
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].type == SBK_WRITE        

    def test_packet_handler_sock(self):
        """packet_handler should store SBK_SOCK data only if verbose=True"""
        buf = '\x00\x00\x00\x01\x00\x03\x00\x02\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08sock'
        self.sbd.verbose = False
        self.sbd.packet_handler(12345, buf)   
        self.sbd.write_db()
        assert len(self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id))==0
        self.sbd.verbose = True
        self.sbd.packet_handler(12345, buf) 
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1  
        assert data[0].type == SBK_SOCK
        
    def test_packet_hander_open(self):
        """packet_handler should store SBK_OPEN data only if verbose=True"""  
        buf = '\x00\x00\x00\x01\x00\x03\x00\x03\x00\x00\x00\x01\x00\x0009\x00\xbc^\xa8\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x17bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08/dev/null'
        self.sbd.verbose = False
        self.sbd.packet_handler(12345, buf) 
        assert len(self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id))==0
        self.sbd.verbose = True
        self.sbd.packet_handler(12345, buf)  
        self.sbd.write_db()
        data = self.sbq.select(Sebek.c.honeypot_id==self.sbd.hp.id)
        assert len(data)==1
        assert data[0].type == SBK_OPEN

    def test_empty_insert(self):
        """shouldn't try and write to db with empty insert_list"""
        self.sbd.insert_list = []
        # insertmany barfs with emtpy list so this is valid test
        self.sbd.write_db()
        
    def test_already_in_db(self):
        """should spot lines already in db and skip"""   
        self.sbd.sbk_keystrokes(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan\n", parent_pid=1, inode=12345)
        self.sbd.write_db()   
        for i in xrange(1, 5):   
            assert self.sbq.count() == 1
            self.sbd.sbk_keystrokes(version=3, t=12345, pid=1, fd=1, uid=1, com="sh", data="./scan\n", parent_pid=1, inode=12345)
            self.sbd.write_db()

if __name__ == '__main__':
    unittest.main()