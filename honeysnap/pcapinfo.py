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

import pcap
import os, time
import base
from output import stringFormatMessage

class pcapInfo(base.Base):

    def __init__(self, filename):
        base.Base.__init__(self)
        self.filename = filename        
        format =  "\
\tFile name: %(filename)s\n \
\tNumber of packets: %(pktcount)d\n \
\tFile size: %(fsize)d bytes \n \
\tData size: %(dsize)d bytes \n \
\tCapture duration: %(duration)s seconds \n \
\tStart time: %(start)s \n \
\tEnd time: %(end)s \n \
\tData rate: %(bytes)s bytes/s \n \
\tData rate: %(bits)s bits/s \n \
\tAverage packet size: %(avg)s bytes \n \
        "
        self.msg = stringFormatMessage(format = format)
    
    def getStats(self):
        p = pcap.pcap(self.filename)
        pktcount = 0
        dsize = 0
        duration = 0
        end  = 0
        bytes = 0
        avg = 0     
        start = 0
        for ts, buf in p:  
            if ts<start or start==0:
                start = ts
            pktcount += 1
            dsize += len(buf)
            if ts>end:
                end = ts
        fsize = os.stat(self.filename).st_size
        duration = end - start 
        if duration == 0:
            self.doOutput('\tFile has zero duration! Cannot generate pcap info')
            return
        start = time.asctime(time.localtime(start))
        end = time.asctime(time.localtime(end))
        bytes = float(dsize)/duration
        bits = bytes*8
        avg = float(dsize)/float(pktcount)
        d = dict(filename=self.filename, pktcount=pktcount, fsize=fsize, dsize=dsize, duration=str(duration), start=start, end=end, bytes=str(bytes), bits=str(bits), avg=str(avg))
        self.msg.msg = d
        self.doOutput(self.msg)

if __name__ == "__main__": 
    import sys 
    f = sys.argv[1]
    i = pcapInfo(f)
    print i.getStats()
            
