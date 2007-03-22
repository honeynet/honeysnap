################################################################################
# (c) 2006, The Honeynet Project
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
import time
import sys

import pcap

class PCapInfo(object):

    def __init__(self, filename): 
        self.filename = filename
        self.p = pcap.pcap(filename)
    
    def get_stats(self):
        start = 0
        end  = 0
        for ts, buf in self.p:  
            if ts<start or start==0:
                start = ts
            if ts>end:
                end = ts
        duration = end - start 
        if duration == 0:
            print('\tFile has zero duration! Cannot generate pcap info')
            sys.exit(1)
        return (start, end)

if __name__ == "__main__": 
    import sys 
    f = sys.argv[1]
    i = pcapInfo(f)
    print i.getStats()
            
