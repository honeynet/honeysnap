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
import tempfile   
import os

import honeysnap.util as hs_util
       
class test_utils(unittest.TestCase):
    """Test util fns"""  
    
    def test_parse_dburi_bad(self):
        """parse_dburi should fail with a bad dburi""" 
        for dburi in ["fred:///fe/fe", "mysql://localhost/db", 
                      "mysql://scott:tiger/db", 
                      "postgre://scott@localhost/db",
                      "postgre://scott:tiger@localhost:a/db",
                      "postgre://scott:tiger@localhost:9999999/db",
                      "postgre://scott:tiger@fred",
                      ]:
            self.assertRaises(ValueError, hs_util.parse_dburi, dburi)

    def test_parse_dburi(self):
        """parse_dburi should parse valid dburis"""
        for dburi, result in [ ("mysql://user:pass@localhost/db", ("localhost", None, "user", "pass", "db", "mysql") ),
                                ("postgre://user:pass@localhost:1234/db", ("localhost", 1234, "user", "pass", "db", "postgre"))
                             ]:      
            assert result == hs_util.parse_dburi(dburi)  
            
    def test_mdsum(self):
        """mdsum should calculate md5 correctly"""
        file = tempfile.NamedTemporaryFile()
        file.write("this is some text to md5")
        file.flush()                                                         
        print hs_util.mdsum(file.name)
        assert hs_util.mdsum(file.name) == "f58c7a5fb06163bf62140671eb52373e"
        file.close()
        
    def test_make_dir(self):
        """make_dir should make a directory"""
        dir = tempfile.mkdtemp()
        hs_util.make_dir("%s/fred" % dir)
        assert os.path.exists("%s/fred" % dir) 

    @raises(SystemExit)
    def test_make_dir_bad(self):
        """make_dir should exit on bad dir"""
        dir = tempfile.mkdtemp()
        hs_util.make_dir("%s/fred/fred" % dir)

    @raises(SystemExit)
    def test_check_pcap_file_no_file(self):
        """check_pcap_file fails if file isn't a pcap file"""
        file = tempfile.NamedTemporaryFile()
        file.write("hi there")
        file.flush()
        hs_util.check_pcap_file(file.name)

    @raises(SystemExit)
    def test_check_pcap_file_empty(self):
        """check_pcap_file fails on empty file"""
        file = tempfile.NamedTemporaryFile()
        hs_util.check_pcap_file(file.name) 
        
        
        
        
                
        
        
        
        
        
        
        
        
        
        