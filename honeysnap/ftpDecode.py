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

import re
from util import renameFile
from flow import reverse as freverse
import tcpflow
import pcap
from flowIdentify import flowIdentify
from flowDecode import flowDecode

cmds = ['STOR', 'STOU', 'RETR', 'LIST', 'NLST', 'APPE']

class ftpDecode(flowDecode):

    def __init__(self):
        super(ftpDecode, self).__init__()
        self.tf = self.options['time_convert_fn']
        self.statemgr = None
        # for some reason the data samples I'm using
        # often have UUUUUUPORT, compensate for that in the RE
        # It turns out these are being stuck in the stream due to duplicate ACKS
        self.activeRE = re.compile("^U*PORT", re.M)
        self.passiveRE = re.compile("PASV")
        self.portIPRE = re.compile("(\d+,){5}\d+") 
        self.userRE = re.compile("USER\s(.*)")
        self.passRE = re.compile("PASS\s(.*)")
        # response code 227 is PASV
        # response code 229 is EPASV
        self._227re = re.compile("^227|^229", re.M)
        self.id = flowIdentify()

    def print_summary(self):            
        """Print summary info"""  
        super(ftpDecode, self).print_summary('\nFTP summary for %s\n\n') 

    def decode(self, state, statemgr):
        self.statemgr = statemgr  
        state.open(flags="rb", statemgr = self.statemgr)
        d = state.fp.readlines()   
        state.close()
        #t, req = self.determineType(d)
        d = "".join(d)
        f = state.flow
        #print '%s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
        if f.dport == 21:
            # ftp control connection
            # use these to figure out filenames for other flows
            m = self.passiveRE.search(d)
            if m is not None:
                self.extractPassive(state, d)
            else:
                # if we didn't find a PASV command, assume active
                self.extractActive(state, d)


    def extractActive(self, state, d):
        #print "Active FTP"
        username, password = "Unknown", "Unknown"
        # look for port lines
        m = self.activeRE.search(d)
        if m is None:
            return
        # split data into a list of lines
        lines = d.splitlines()
        iterlines = iter(lines)
        for l in iterlines:  
            m = self.userRE.search(l)
            if m:
                username = m.group(1) 
                continue 
            m = self.passRE.search(l)
            if m:
                password = m.group(1)
                continue       
            if l.find("PORT")>=0:
                try:
                    nextl = iterlines.next()
                except StopIteration:
                    return
                if nextl.find("RETR")>=0:
                    # this means the current PORT will be
                    # a data channel for a downaload
                    filename = nextl.split(" ")[1]
                    ip_port = l.split(" ")[1].split(",")
                    #ip = ".".join(ip_port[0:4])
                    port = int(ip_port[4])*256 + int(ip_port[5])
                    # now we know the ip and port of the client
                    # data channel.
                    # find the correct state
                    # it will look like the reverse flow, with a different dport
                    rflow = freverse(state.flow)
                    rflow.dport = port
                    rflow.sport = 20
                    # find the state that carries the data
                    rstate = self.statemgr.find_flow_state(rflow)
                    # rename the data file
                    if rstate is not None:
                        fn = renameFile(rstate, filename)
                        id, m5 = self.id.identify(rstate)  
                        output = "%s requested %s from %s (%s, %s) at %s\n\tfile: %s, filetype: %s, md5 sum: %s\n" % (rstate.flow.dst, filename, 
                            rstate.flow.src, username, password, self.tf(rstate.ts), fn, id, m5)
                        self.add_flow(rstate.ts, rstate.flow.src, rstate.flow.dst, output)

    def extractPassive(self, state, d): 
        #print "Passive FTP"  
        username, password = "Unknown", "Unknown"
        # repr(port/256), repr(port%256)
        # first we have to find the reverse flow/state
        # from it we will extract the ip and port info
        rflow = freverse(state.flow)
        rstate = self.statemgr.find_flow_state(rflow)
        if rstate is None:
            # no reverse state, bail
            return 
        rstate.open(flags="rb", statemgr=self.statemgr)
        dchannel = rstate.fp.readlines()
        rstate.close()
        lines = d.splitlines()
        iterlines = iter(lines)
        portlines = []
        cmdlines = []
        # find all the lines from the server
        # that open a data port
        # find all the 227 lines in the data channel
        for l in dchannel:  
            m = self._227re.search(l)
            if m is not None:
                portlines.append(l)
        # find all the client lines that use
        # a data port
        for l in lines:             
            m = self.userRE.search(l)
            if m:
                username = m.group(1) 
                continue
            else:
                username = "Unknown"
            m = self.passRE.search(l)
            if m:
                password = m.group(1)
                continue           
            else:
                password = "Unknown"
            w = [i for i in cmds if i in l.split()[0]]
            if len(w) == 0:
                # this line doesn't contain a data command
                continue
            cmdlines.append(l)
        # zip the 2 lists together
        # should give [(227 response, Client CMD),...]
        pairs = zip(portlines, cmdlines)
        for p in pairs:
            if p[1].find("RETR") < 0:
                # not a RETR command
                continue
            m = self.portIPRE.search(p[0])
            if m is not None:
                # the last 2 items in the RE result are the port info
                info = m.group().split(",")
                p256 = int(info[-2])
                p1 = int(info[-1])
                ip = ".".join(info[0:4])
                port = 256*p256 + p1
            else:
                continue
            filename = p[1].split(" ")[1]
            rflow.sport = port
            # passive ftp transactions happen on high ports
            # so the stream extractor has not extracted the data
            # create a new stream extractor to pull the data
            p = pcap.pcap(self.options["tmpf"])
            de = tcpflow.tcpFlow(p)
            filter = "src host %s and src port %d" % (rflow.src, rflow.sport)
            de.setFilter(filter)
            de.setOutdir(self.options["output_data_directory"]+ "/%s/ftp")
            # run the flow extractor 
            de.start()
            # now find the correct state
            flows  = [f for f in de.states.getFlows() if f.isSrcSport(ip, port)]
            if len(flows) > 0:
                if len(flows) > 1:
                    print "hmmm, got more than 1 flow"
                rflow = flows[0]
            rstate = de.states.find_flow_state(rflow)
            # rename the data file
            if rstate is not None:
                fn = renameFile(rstate, filename)
                id, m5 = self.id.identify(rstate)    
                output = "%s requested %s from %s (%s, %s) at %s\n\tfile: %s, filetype: %s, md5 sum: %s\n" % (rstate.flow.dst, filename, 
                    rstate.flow.src, username, password, self.tf(rstate.ts), fn, id, m5)                
                self.add_flow(rstate.ts, rstate.flow.src, rstate.flow.dst, output)



