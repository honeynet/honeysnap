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

class test_ircDecode(unittest.TestCase):
    def setUp(self):
        self.engine = connect_to_db('sqlite:///')
        IrcDecode.__init__ = lambda self: None
        self.ircd = IrcDecode()
        self.ircd.hash = {}
        self.ircd.insert_list = []       
        self.session = create_session()
        self.ircd.hp = Honeypot.get_or_create(self.session, '192.168.0.1')   
        self.session.flush()

    def tearDown(self):
        self.session.clear() 
        metadata.drop_all()        

    def test_raw_message(self):
       """shouldn't store messages of type all_raw_messages in db"""
       assert 1 == 0
       
    def test_max_data_size(self):
       """should restict max data size"""
       assert 1 == 0
       
    def test_max_command_size(self):
       """shold restrict max command size"""
       assert 1 == 0
       
    def test_create_new_talker(self):
       """should create new talker if it doesn't exist"""
       assert 1 == 0
       
    def test_existing_talker(self):
       """should not create talker if we have seen it before"""
       assert 1 == 0
       
    def test_dup_lines(self):
       """shouldn't try and store dup lines in insert_list"""
       assert 1 == 0
                                        
    def test_already_in_db(self):
       """should spot lines already in db and skip"""
       assert 1 == 0
       
    def test_empty_insert_list(self):
       """shouldn't try and write to db if insert_list is emptry"""
       assert 1 == 0

    
if __name__ == '__main__':
    unittest.main()