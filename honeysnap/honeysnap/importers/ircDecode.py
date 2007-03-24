################################################################################
# (c) 2006, The Honeynet Project
#   Author: Arthur Clune arthur@honeynet.org.uk
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

from honeysnap.importers.hsIRC import HoneysnapIRC   
from honeysnap.singletonmixin import HoneysnapSingleton  
from honeysnap.model.model import *

class IrcDecode(object):
    """
    Stuff IRC data into db
    """

    def __init__(self, tmpf, file, hp):  
        """Create object"""      
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()  
        self.tmpf = tmpf
        self.file = file
        self.hpip = hp
        self.ircports = []
        self.engine = connect_to_db(options['dburi'], options['debug']) 
        self.session = create_session()
        self.hp = Honeypot.get_or_create(self.session, hp) 
        self.count = 0

    def run(self):
        """run over file for one honeypot and a set of ports"""
        # work out ports
        for port in [6667]:
            hirc = HoneysnapIRC()
            hirc.connect(self.tmpf, "host %s and tcp and port %s" % (self.hpip, port) )
            hirc.addHandler("all_events", self.decode, -1)
            hirc.ircobj.process_once()    
            self.hp.save_irc_changes(self.session)
         
    def decode(self, c, e):
        """
        Callback to register with HoneySnapIRC
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        """ 
        self.count += 1      
        if e.eventtype() == 'all_raw_messages':
            return
        src_id = Ip.id_get_or_create(e.src)
        dst_id = Ip.id_get_or_create(e.dst)
        data = ' '.join(e.arguments())      
        source = e.source()
        target = e.target()
        if source == None:
            source = e.src
        if target == None:
            target = e.dst
        src_id = IRCTalker.id_get_or_create(source)
        dst_id = IRCTalker.id_get_or_create(target)    
        #print "%s e.src: %s e.dst: %s, source: %s, target:%s, command: %s, text: %s" % (e.time, e.src, e.dst, e.source(), e.target(), e.eventtype(), data)
        m = IRCMessage(src_id=src_id, dst_id=dst_id, sport=e.sport, dport=e.dport, 
                       from_id=src_id, to_id=dst_id, command=e.eventtype(), 
                       timestamp=e.time, text=data)          
        self.hp.irc_messages.append(m)  
        if not self.count % 1000:
            self.hp.save_irc_changes(self.session)
        
if __name__ == '__main__': 
    import sys 
    from honeysnap.importers.hsIRC import HoneySnapIRC    
    
    print 'Looking at file %s host %s' % (sys.argv[1], sys.argv[2])
    hirc = HoneysnapIRC()
    hirc.connect(sys.argv[1], "host %s and tcp and port %s" % (sys.argv[2], 6667))
    hd = ircDecode()
    hirc.addHandler("all_events", hd.decodeCB, -1)
    hirc.ircobj.process_once()
        
        
        
