################################################################################
# (c) 2005, The Honeynet Project
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

import sys
import socket
from optparse import OptionParser, Option, OptionValueError
import re
import string
import time
import os
from fnmatch import fnmatch
import ConfigParser
from ConfigParser import SafeConfigParser
import tempfile
import pkg_resources       
from datetime import datetime

import pcap

# all the honeysnap imports
from pcapinfo import PCapInfo
from flowIdentify import FlowIdentify
from sebekDecode import SebekDecode         
from honeysnap.singletonmixin import HoneysnapSingleton
from honeysnap.util import make_dir, check_pcap_file
                                    
VERSION=pkg_resources.get_distribution('honeysnap')

def main():
    """
    Set everything off and handle files/stdin etc
    """
    print_help, options, args = parseOptions()
    if len(sys.argv)>1:
        if options['honeypots'] is None:
            print "No honeypots specified. Please use either -H or config file to specify honeypots.\n"
            sys.exit(2)
        hsingleton = HoneysnapSingleton.getInstance(options)
        # by default treat args as files to be processed
        # handle multiple files being passed as args
        if len(args):
            for f in args:
                if os.path.exists(f) and os.path.isfile(f):
                    processFile(f)
                else:
                    print "File not found: %s" % f
                    sys.exit(2)
        # no args indicating files, read from stdin
        else:
            # can't really do true stdin input, since we repeatedly parse
            # the file, so create a tempfile that is read from stdin
            # pass it to processFile
            fh = sys.stdin
            tmph, tmpf = tempfile.mkstemp()
            tmph = open(tmpf, 'wb')
            for l in fh:
                tmph.write(l)
            tmph.close()
            processFile(tmpf)
            # all done, delete the tmp file
            os.unlink(tmpf)
    else:
        print_help()

def processFile(file):
    """
    Process a pcap file 'file'.
    """
    hs = HoneysnapSingleton.getInstance()
    options = hs.getOptions()
    file = os.path.abspath(file)
    tmpf, deletetmp = check_pcap_file(file)
    
    print "Analysing file: %s" % file
    # always get pcap info to find starttime and endtime 
    print "Getting pcap info for %s" % file
    pi = PCapInfo(tmpf)
    starttime, endtime = pi.get_stats()
    hs.setOption('starttime', datetime.utcfromtimestamp(starttime))
    hs.setOption('endtime', datetime.utcfromtimestamp(endtime))    

    for hp in options["honeypots"]:
        print "Importing connections for %s" % hp
        s = FlowIdentify(tmpf, file, hp)
        filt = 'host %s' % hp
        s.setFilter(filt)
        s.start()

    for hp in options["honeypots"]:
        print "Importing sebek data for honeypot %s" % hp
        sbd = SebekDecode(tmpf, file, hp)
        sbd.run()
                  
    # delete the tmp file we used to hold unzipped data
    if deletetmp:
        os.unlink(tmpf)

def parseOptions():
    """
    Read options from both config file and command line and merge
    Precedence order: Command line > config file > defaults

    Returns a (help, options, args) tuple. Help is a function that prints help
    """

    # default values for all options.
    defaults = {                   
        'config'            : None,
        'honeypots'         : None,
        'dburi'             : 'sqlite:///fred.db',
        'debug'             : False,   
        'sebek_port'        : 1101,
        'sebek_all_data'    : False,
    }

    parser = OptionParser(version="%s" % VERSION)

    parser.add_option("-c", "--config", dest="config",type="string", 
        help="Config file")
    parser.add_option("-H", "--honeypots", dest="honeypots", type="string",
        help="Comma delimited list of honeypots")
    parser.add_option("--dburi", dest="dburi", type="string", 
        help="Uri used to connect to target database")
    parser.add_option("--debug", dest="debug", action="store_const", const=True,
        help="Enabled DB debugging")
    parser.add_option("--sebek-port", dest="sebek_port", type="int",
        help = "Port for sebek traffic (default 1101)")
    parser.add_option("--sebek-all-data", dest="sebek_all_data", action="store_const", const=True, 
        help = "Extract all sebek data? Warning - produces a very large amount of data (gigabytes)") 
        
    (cmdopts, args) = parser.parse_args()
                              
    # now pull in config file if defined
    if cmdopts.config:
        cp = ConfigParser.ConfigParser()
        try:
            cp.read(cmdopts.config) 
            defaults.update(dict(cp.items('IO')))
            defaults.update(dict(cp.items('OPTIONS')))
        except ConfigParser.Error:
            print "Problem with the config file! Check format and permissions"
            sys.exit(1)

    # command line over-rides config 
    for k, v in cmdopts.__dict__.iteritems():  
        if v:
            defaults[k] = v

    if not defaults['honeypots']: 
        parser.print_help()
        print "No honeypots specified! Please use either -H or the config file to specify some"
        sys.exit(1)
    
    for k in ['honeypots']:
        defaults[k] = defaults[k].split(',')
    for k in ['sebek_port']:
        try:           
            defaults[k] = int(defaults[k])
        except ValueError:
            pass                  

    return (parser.print_help, defaults, args)  

def start():
    """
    This is nothing but an entry-point for setuptools in which we can trap ctrl-c
    """
    try:
        main()
    except KeyboardInterrupt:
        print 'Caught KeyboardInterrupt - Goodbye!'
        sys.exit(0)




