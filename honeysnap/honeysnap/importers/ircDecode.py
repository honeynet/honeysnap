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

from datetime import datetime 
from socket import inet_aton

import sqlalchemy 
import dpkt 
import pcap                      

from honeysnap.importers.hsIRC import HoneysnapIRC   
from honeysnap.importers.pcapRE import PcapReCounter
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
        self.irc_ports = options['irc_ports'][hp]
        self.tmpf = tmpf
        self.file = file
        self.hpip = hp
        self.insert_list = []
        self.hash = {}
        self.engine = connect_to_db(options['dburi'], options['debug']) 
        self.session = create_session()                        
        self.hp = hp
        self.hpid = Honeypot.get_or_create(self.session, hp).id
        self.count = 0
            
    def run(self):
        """run over file for one honeypot and a set of ports"""
        self.find_irc_ports()
        if self.irc_ports:
            print "\tTrying to decode IRC on port(s) ", self.irc_ports
        else:       
            print "\tNo IRC seen"
            return
        for port in self.irc_ports:
            hirc = HoneysnapIRC()
            hirc.connect(self.tmpf, "host %s and tcp and port %s" % (self.hpip, port) )
            hirc.addHandler("all_events", self.decode, -1)
            hirc.ircobj.process_once()   
            self.write_db()  
            print '\tProcessed %s IRC messages' % self.count

    def find_irc_ports(self):
        """
        spot IRC traffic by looking for 'PRIVMSG', appending
        any found ports to our existing list
        """
        p = pcap.pcap(self.tmpf)
        r = PcapReCounter(p)
        r.set_filter("host %s and tcp" % self.hp)
        r.set_re('PRIVMSG')
        r.start()                         
        self.irc_ports = r.server_ports(self.irc_ports) 
         
    def decode(self, c, e):
        """
        Callback to register with HoneySnapIRC
        c: instance of hsIRC.HnyServerConnection
        e: instance of irclib.Event
        """      
        if e.eventtype() == 'all_raw_messages':
            return 
        self.count += 1             
        src_id = Ip.id_get_or_create(e.src)
        dst_id = Ip.id_get_or_create(e.dst)
        data = ' '.join(e.arguments())      
        source = e.source()
        target = e.target()   
        if source == None:
            source = e.src
        if target == None:
            target = e.dst
        irc_src_id = IRCTalker.id_get_or_create(source)
        irc_dst_id = IRCTalker.id_get_or_create(target)
        m = dict(honeypot_id=self.hpid, src_id=src_id, dst_id=dst_id, sport=e.sport, dport=e.dport, 
                       from_id=irc_src_id, to_id=irc_dst_id, command=e.eventtype()[0:MAX_IRC_COMMAND_SIZE], 
                       timestamp=datetime.fromtimestamp(e.time), text=data[0:MAX_IRC_TEXT_SIZE], filename=self.file)  
        self.save(m) 
        if not self.count % 10000:
            print '\tProcessed %s IRC messages' % self.count
            self.write_db()
        
    def save(self, m): 
        if self.hash.has_key(str(m)):
            return
        self.hash[str(m)] = 1
        self.insert_list.append(m)
        
    def write_db(self): 
        save_table(irc_message_table, self.insert_list)
        self.hash = {}
        self.insert_list = []
        