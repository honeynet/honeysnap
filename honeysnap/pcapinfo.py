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

import dpkt
import os, time
import base
from output import stringFormatMessage

class pcapInfo(base.Base):

    def __init__(self, filename):
        base.Base.__init__(self)
        self.filename = filename        
        format =  " \
File name: %(filename)s\n \
Number of packets: %(pktcount)d\n \
File size: %(fsize)d bytes \n \
Data size: %(dsize)d bytes \n \
Capture duration: %(duration)s seconds \n \
Start time: %(start)s \n \
End time: %(end)s \n \
Data rate: %(bytes)s bytes/s \n \
Data rate: %(bits)s bits/s \n \
Average packet size: %(avg)s bytes \n \
        "
        self.msg = stringFormatMessage(format = format)
    
    def getStats(self):
        f = open(self.filename)
        pr = dpkt.pcap.Reader(f)
        pktcount = 0
        dsize = 0
        duration = 0
        start = 0
        end  = 0
        bytes = 0
        avg = 0
        for p in pr:
            if start == 0:
                start = p[0]
            pktcount += 1
            dsize += len(p[1])
            end = p[0]
            
        fsize = os.stat(self.filename).st_size
        duration = end - start
        start = time.asctime(time.localtime(start))
        end = time.asctime(time.localtime(end))
        bytes = float(dsize)/duration
        bits = bytes*8
        avg = float(dsize)/float(pktcount)
        f.close()
        d = dict(filename=self.filename, pktcount=pktcount, fsize=fsize, dsize=dsize, duration=str(duration), start=start, end=end, bytes=str(bytes), bits=str(bits), avg=str(avg))
        self.msg.msg = d
        self.doOutput(self.msg)

if __name__ == "__main__":
    i = pcapInfo('/Users/jed/src/honeynet/roo/20050227')
    print i.getStats()
            
