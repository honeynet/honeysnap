################################################################################
# (c) 2006, The Honeynet Project
#   Authors: Jeff Nathan and Arthur Clune
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

#from irclib import is_channel, ip_numstr_to_quad, ip_quad_to_numstr, nm_to_n
#from irclib import nm_to_uh, nm_to_h, nm_to_u, parse_nick_modes
#from irclib import parse_channel_modes, _linesep_regexp, _parse_modes
from irclib import *
from irclib import _linesep_regexp, _parse_modes, _rfc_1459_command_regexp
from irclib import _ctcp_dequote
import dpkt
#import dnet     
import irclib
import math
import optparse
import pcap
import time
from datetime import datetime
from socket import inet_ntoa
       
       
class HnyEvent(irclib.Event):
    """
    subclass Event so we can pass in pkt header info
    and store timestamp + IP + TCP info
    """ 
    def __init__(self, ts, pkt, eventtype, source, target, arguments=None): 
        irclib.Event.__init__(self, eventtype, source, target, arguments)
        self.time  = datetime.fromtimestamp(ts)
        self.src   = inet_ntoa(pkt.src)
        self.dst   = inet_ntoa(pkt.dst)
        self.dport = pkt.data.dport
        self.sport = pkt.data.sport

class HnyServerConnection(irclib.ServerConnection):
    def __init__(self, irclibobj):
        Connection.__init__(self, irclibobj)
        self.handlers = {}

    def connect(self, pcapfile, filter):
        self.previous_buffer = ''
        self.real_server_name = 'HoneySnap'
        self.real_nickname = 'HoneySnap'
        self.pc = pcap.pcap(pcapfile, promisc=False)
        self.pc.setfilter(filter)

    def process_data(self, ts, pkt):
        new_data = pkt.tcp.data
        # save the packet
        self.pkt = pkt
        # save the timestamp
        self.ts = ts                
        """
        print "%s %s:%s -> %s:%s\n%s" % (datetime.fromtimestamp(ts), dnet.addr(pkt.src), pkt.data.sport, 
                                      dnet.addr(pkt.dst), pkt.data.dport)
                                      dpkt.hexdump(str(new_data)))
        """
        lines = _linesep_regexp.split(self.previous_buffer + str(new_data))

        # Save the last, unfinished line.
        self.previous_buffer = lines[-1]
        lines = lines[:-1]

        for line in lines:
            if DEBUG:
                print "FROM SERVER:", line

            if not line:
                continue

            line = line.lstrip()
            prefix = None
            command = None
            arguments = None
            self._handle_event(HnyEvent(ts, self.pkt, "all_raw_messages",
                                     self.get_server_name(),
                                     None,
                                     [line]))

            m = _rfc_1459_command_regexp.match(line)
            if not m:
                raise IRCError
            
            if m.group("prefix"):
                prefix = m.group("prefix")
                #print "***********PREFIX**************: %s" % prefix
                if not self.real_server_name:
                    self.real_server_name = prefix

            if m.group("command"):
                command = m.group("command").lower()

            if m.group("argument"):
                a = m.group("argument").split(" :", 1)
                arguments = a[0].split()
                if len(a) == 2:
                    arguments.append(a[1])

            # Translate numerics into more readable strings.
            if command in numeric_events:
                command = numeric_events[command]

            if command == "nick" and prefix is not None:
                #print "***********PREFIX**************: %s" % prefix
                if nm_to_n(prefix) == self.real_nickname:
                    self.real_nickname = arguments[0]
            elif command == "welcome":
                # Record the nickname in case the client changed nick
                # in a nicknameinuse callback.
                self.real_nickname = arguments[0]

            if command in ["privmsg", "notice"]:
                target, message = arguments[0], arguments[1]
                messages = _ctcp_dequote(message)

                if command == "privmsg":
                    if is_channel(target):
                        command = "pubmsg"
                else:
                    if is_channel(target):
                        command = "pubnotice"
                    else:
                        command = "privnotice"

                for m in messages:
                    if type(m) is types.TupleType:
                        if command in ["privmsg", "pubmsg"]:
                            command = "ctcp"
                        else:
                            command = "ctcpreply"

                        m = list(m)
                        if DEBUG:
                            print "command: %s, source: %s, target: %s," \
                                  " arguments: %s" % (command, prefix, target, 
                                                      m)
                        self._handle_event(HnyEvent(ts, self.pkt, command, prefix, target, m))
                        if command == "ctcp" and m[0] == "ACTION":
                            self._handle_event(HnyEvent(ts, self.pkt, "action", prefix, target, 
                                                     m[1:]))
                    else:
                        if DEBUG:
                            print "command: %s, source: %s, target: %s," \
                                  " arguments: %s" % (command, prefix, target, 
                                                      [m])
                        self._handle_event(HnyEvent(ts, self.pkt, command, prefix, target, [m]))
            else:
                target = None

                if command == "quit":
                    arguments = [arguments[0]]
                elif command == "ping":
                    target = arguments[0]
                elif arguments is not None:
                    target = arguments[0]
                    arguments = arguments[1:]

                if command == "mode":
                    if not is_channel(target):
                        command = "umode"

                if DEBUG:
                    print "command: %s, source: %s, target: %s," \
                          " arguments: %s" % (command, prefix, target, 
                                              arguments)
                self._handle_event(HnyEvent(ts, self.pkt, command, prefix, target, arguments))

class HnyIRC(irclib.IRC):
    def __init__(self):
        self.connections = []
        self.handlers = {}
        # list of tuples in the form (time, function, arguments)
        # self.delayed_commands = []    # XXX - do we need this ?

    def server(self):
        c = HnyServerConnection(self)
        self.connection = c
        return c
        
    def process_data(self, ts, data):
        self.connection.process_data(ts, data)

    def process_once(self, timeout=0):
        for ts, pkt in self.connection.pc:
            ip = dpkt.ip.IP(pkt[self.connection.pc.dloff:])
            try:
                self.process_data(ts, ip)
            except IRCError:
                # uncomment the next 3 lines to debug irc decode errors
                #import pdb, traceback
                #traceback.print_exc(file=sys.stdout)
                #pdb.post_mortem(sys.exc_traceback)
                print "ERROR on:\n%s" % dpkt.hexdump(str(ip.tcp.data))
                continue

    def process_forever(self, timeout=0):
        return self.process_once()
    
class HoneySnapIRC(irclib.SimpleIRCClient):
    def __init__(self):
        self.ircobj = HnyIRC()
        self.connection = self.ircobj.server()
        self.ircobj.add_global_handler("all_events", self._dispatcher, -10)
        #self.ircobj.add_global_handler("all_events", self.on_global, -1)

    def connect(self, pcapfile, filter=''):
        if not filter or filter == '':
            filter = "tcp and port 6667"
        self.connection.connect(pcapfile, filter)

    def on_global(self, c, e):
        if e.eventtype() != 'ping' and e.eventtype() != 'all_raw_messages':
            print "%s\t%s:%s -> %s:%s\t%s\t%s\t%s\t%s" % (e.time, e.src, e.sport, e.dst, e.dport,
                                          e.eventtype(), e.source(),
                                          e.target(), ' '.join(e.arguments()))
                                          
    def addHandler(self, type, func, priority):
        """
        arguments:
        type: string specifying the eventtype
        func: the callback function, takes 2 args: connection object and irclib.Event
        priority: an integer the higher the number, the higher the priority
        """
        self.ircobj.add_global_handler(type, func, priority)


if __name__ == '__main__': 
    """Quick demo to print out IRC"""
    op = optparse.OptionParser()
    op.add_option('-f', '--file', dest='file', help='pcap file to parse')
    opts, args = op.parse_args()
    if not opts.file:
        op.error('a pcap file must be specified')
        sys.exit(1)

    if args:
        filter = ' '.join(args)
    else:
        filter = ''
    h = HoneySnapIRC()    
    h.ircobj.add_global_handler("all_events", h.on_global, -1)
    h.connect(opts.file, filter)
    h.ircobj.process_once()
