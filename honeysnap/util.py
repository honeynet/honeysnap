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

def ipnum(ip) :
    "Return a numeric address for an ip string"
    v = 0L
    for x in ip.split(".") :
        v = (v << 8) | int(x);
    return v

def findName(filename, realname):
    head, tail = os.path.split(filename)
    newfn = head+'/'+realname+".1"
    while 1:
        if os.path.exists(newfn):
            newfn, ext = newfn.rsplit(".", 1)
            ext = int(ext)+1
            newfn = newfn + "." +str(ext)
        else:
            return newfn
            
def renameFile(state, realname):
    state.realname = realname
    newfn = findName(state.fname, realname)
    #print "\n%s %s" %(state.fname, newfn)   
    try:
        os.rename(state.fname, newfn)
    except OSError, e:
        # file too long probably 
        print "Failed to rename file %s to %s, reason %s" % (state.fname, newfn, e)
        return state.fname
    state.fname = newfn
    return newfn  

def mdsum(file):
    m = md5.new()
    f = open(file, "r")
    m.update("".join(f.readlines()))
    d = m.hexdigest()
    #print "md5: %s" % d
    return d

def orderByValue(d, rev=True, limit=0):
    """
    Given a dictionary, returns a list of tuples (key, value), sorted
    by the value of each entry, limited to the top N values if limit>0
    """                             
    if limit==0:               
        return sorted(d.iteritems(), key=itemgetter(1), reverse=rev)     
    else:                                                           
        return sorted(d.iteritems(), key=itemgetter(1), reverse=rev)[0:limit]
    
    
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
    except IOError, e:
        # got an error, must not be gzipped
        # should probably do a better check here
        print 'Got an IO Error ', e
        tmpf = file
        is_tempfile = False 
    # quick and dirty check file is a valid pcap file
    try:
        if os.path.exists(tmpf) and os.path.getsize(tmpf)>0 and os.path.isfile(tmpf):
            p = pcap.pcap(tmpf)
    except OSError:
        print "File %s is not a pcap file or does not exist" % file
        sys.exit(1) 
    return (tmpf, is_tempfile)
    
