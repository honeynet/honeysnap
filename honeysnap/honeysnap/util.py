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

import os
import md5       
import sys
from operator import itemgetter
import tempfile
import pcap 
import gzip

def parse_dburi(uri):
    "Turn the connection_string into a series of parameters to the connect method"
    # based on http://www.halfcooked.com/code/dburi.py 
    (host, port, username, password, dbName, db_type) = (None, None, None, None, None, None)
    db_type, connection_string = uri.split(':/')
    # Strip the leading '/'
    if connection_string.startswith('/'):
        connection_string = connection_string[1:]
    if connection_string.find('@') != -1:
        # Split into the username (and password) and the rest
        username, rest = connection_string.split('@')
        if username.find(':') != -1:
            username, password = username.split(':')
        # Take the rest and split into its host, port and db name parts
        if rest.find('/') != -1:
            host, dbName = rest.split('/')
        else:
            host = rest
            dbName = ''
        if host.find(':') != -1:
            host, port = host.split(':')
            try:
                port = int(port)
            except ValueError:
                raise ValueError, "port must be integer, got '%s' instead" % port
            if not (1 <= port <= 65535):
                raise ValueError, "port must be integer in the range 1-65535, got '%d' instead" % port
        else:
            port = None
    else:
        raise ValueError, "Bad dburi"
    if not (host and username and password and dbName and db_type):
        raise ValueError, "Bad dburi"
    return (host, port, username, password, dbName, db_type)
   
def mdsum(file):
    m = md5.new()
    f = open(file, "r")
    m.update("".join(f.readlines()))
    d = m.hexdigest()
    #print "md5: %s" % d
    return d

def make_dir(path):
    """Create a dir, print nice error if we fail"""
    if not os.path.exists(path):
        try:
            os.mkdir(path)
        except OSError:
            print "Unable to create dir: %s Check permissions." % (path)
            sys.exit(2)    
                                      
def check_pcap_file(file):
    """Return a path to a valid pcap file, ungzipping if needed
    Returns a (filename, tempfile) pair where tempfile is a boolean
    indicating if we are returning a temp file 
    """   
    BLOCK_SIZE = 2 ** 20    
    try:
        # This sucks. pcapy wants a path to a file, not a file obj
        # so we have to uncompress the gzipped data into
        # a tmp file, and pass the path of that file to pcapy
        tmph, tmpf = tempfile.mkstemp()
        tmph = open(tmpf, 'wb')
        gfile = gzip.open(file)
        for i in iter(lambda: gfile.read(BLOCK_SIZE), ''):
            tmph.write(i)        
        gfile.close()
        tmph.close()
        is_tempfile = True
    except IOError:
        # got an error, must not be gzipped
        # should probably do a better check here
        tmpf = file
        is_tempfile = False 
    # quick and dirty check file is a valid pcap file
    try:
        if os.path.exists(tmpf) and os.path.getsize(tmpf)>0 and os.path.isfile(tmpf):
            p = pcap.pcap(tmpf)
        else:
            print "File is empty or not a valid file"
            sys.exit(1)
    except (OSError, SystemError):
        print "File %s is not a pcap file or does not exist" % file
        sys.exit(1) 
    return (tmpf, is_tempfile)
    
