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

def orderByValue(d, rev=True):
    """
    Given a dictionary, returns a list of tuples (key, value), sorted
    by the value of each entry
    """
    return sorted(d.iteritems(), key=itemgetter(1), reverse=rev)     
    
    
def make_dir(path):
    """Create a dir, print nice error if we fail"""
    if not os.path.exists(path):
        try:
            os.mkdir(path)
        except OSError:
            print "Unable to create dir: %s Check permissions." % (path)
            sys.exit(2)    
