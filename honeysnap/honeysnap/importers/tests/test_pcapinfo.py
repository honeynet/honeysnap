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
import tempfile        
from datetime import datetime
from nose.tools import raises                                       

from honeysnap.importers.pcapinfo import PCapInfo                      

class test_pcapinfo(unittest.TestCase):   
    """Test pcapinfo"""
    
    def setUp(self):   
        PCapInfo.__init__ = lambda self: None 
                                                
    @raises(SystemExit)
    def test_pcapinfo_zerolen(self):
        """pcapinfo should exit on zero-duration capture"""
        pcap_info = PCapInfo()
        pcap_info.p = [ (1234567, "this isn't pcap data :)") ]
        pcap_info.get_stats()

    def test_pcapinfo(self):
        """pcapinfo should calculate duration correctly"""
        pcap_info = PCapInfo()
        for data, starttime, endtime in [ ([ (123, ""), (023, ""), (456, "") ], 023, 456),
                                          ([ (213, ""), (456, "")], 213, 456),
                                          ([ (001, ""), (011, ""), (999, ""), (022, "")], 001, 999),
            ]:
            pcap_info.p = data
            result = pcap_info.get_stats()  
            print data, starttime, endtime, result
            assert datetime.utcfromtimestamp(starttime), datetime.utcfromtimestamp(endtime) == result
