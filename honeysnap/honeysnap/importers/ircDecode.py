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

from honeysnap.importers.hsIRC import HoneySnapIRC   
from honeysnap.singletonmixin import HoneysnapSingleton

class ircDecode(object):
    """
    Stuff IRC data into db
    """

    def __init__(self):        
        #hs = HoneysnapSingleton.getInstance()
        #options = hs.getOptions()
        pass
         
    def decodeCB(self, c, e):
        """
        Callback to register with HoneySnapIRC
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        """     
        print 'hi'
        cmd = e.eventtype()
        source = e.source()
        target = e.target() 
        srcip = e.src
        dstip = e.dst
        sport = e.sport
        dport = e.dport   
        data = ' '.join(e.arguments())
        ts = e.time
        print 'creating an IRC object for...', ts, cmd, source, target, data
        
if __name__ == '__main__': 
    import sys 
    from honeysnap.importers.hsIRC import HoneySnapIRC    
    
    print 'Looking at file %s host %s' % (sys.argv[1], sys.argv[2])
    hirc = HoneySnapIRC()
    hirc.connect(sys.argv[1], "host %s and tcp and port %s" % (sys.argv[2], 6667))
    hd = ircDecode()
    hirc.addHandler("all_events", hd.decodeCB, -1)
    hirc.ircobj.process_once()
        
        
        
