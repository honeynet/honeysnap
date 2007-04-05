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
import sys
import tempfile
from nose.tools import raises                                       

from honeysnap.importers.main import parse_options

class test_pcapinfo(unittest.TestCase):   
    """Test pcapinfo"""
    
    @raises(SystemExit)
    def test_empty_config_file(self):
        """parse_options should exit on empty config file"""
        file = tempfile.NamedTemporaryFile()                        
        sys.argv = ['honeysnap', '-c', file.name]
        print_help, options, arg = parse_options()      

    @raises(SystemExit)
    def test_bad_config_file(self):
        """parse_options should take exit on bad config file"""
        file = tempfile.NamedTemporaryFile()
        file.write("fred\n")
        file.flush()
        sys.argv = ['honeysnap', '-c', file.name]
        print_help, options, arg = parse_options()        
       
    @raises(SystemExit)
    def test_no_honeypots(self):
        """parse_options should exit if no honeypots specified"""
        sys.argv = ['honeysnap']
        print_help, options, arg = parse_options()        
                                                 
    @raises(SystemExit)
    def test_sebek_int(self):
        """parse_options should exit if sebek_port is not an int"""
        sys.argv = ['honeysnap', '-H', '192.168.0.1', '--sebek-port', 'a']
        print_help, options, arg = parse_options()        

    def test_command_over_default(self):
        """parse_options should take command line options over defaults"""
        sys.argv = ['honeysnap', '-H', '192.168.0.1', '--sebek-port', '11']
        print_help, options, arg = parse_options()        
        assert options['sebek_port'] == 11
                                                                      
    def test_config_over_default(self):
        """parse_options should take config file over defaults"""
        file = tempfile.NamedTemporaryFile(mode="w")
        file.write("[IO]\n")
        file.write("honeypots=192.168.0.1\n")
        file.write("[OPTIONS]\n")
        file.write("sebek_port=22\n")
        file.flush()
        sys.argv = ['honeysnap', '-c', file.name]
        print_help, options, arg = parse_options()        
        assert options['honeypots'] == ['192.168.0.1']
        assert options['sebek_port'] == 22
        
    def test_command_over_config(self):
        """parse_options should take command line opts over config file opts"""
        file = tempfile.NamedTemporaryFile(mode="w")
        file.write("[IO]\n")
        file.write("honeypots=192.168.0.1\n")
        file.write("[OPTIONS]\n")
        file.write("sebek_port=22\n")
        file.flush()
        sys.argv = ['honeysnap', '-c', file.name, '-H', '192.168.0.2', '--sebek-port', '2222']
        print_help, options, arg = parse_options()        
        assert options['honeypots'] == ['192.168.0.2']
        assert options['sebek_port'] == 2222        
        
    def test_honeypot_list(self):
        """parse_options should split honeypots on comma"""
        sys.argv = ['honeysnap', '-H', '192.168.0.1,192.168.0.2']
        print_help, options, arg = parse_options()
        assert options['honeypots'] == ['192.168.0.1', '192.168.0.2']  







        