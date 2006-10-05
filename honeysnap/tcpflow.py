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

import os, sys, shelve, tempfile, re
import impacket
import socket
import pcapy
from pcapy import *
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import traceback
import dpkt
from flow import flow, flow_state, flow_state_manager, reverse, fileHandleError

FLOW_FINISHED=(1 << 0)
FLOW_FILE_EXISTS=(1 << 1)

class tcpFlow:

    def __init__(self, pcapObj):
        # create a tmp file to hold the shelve
        #self.shelf = tempfile.mkstemp()[1]
        #os.unlink(self.shelf)
        #self.flows = shelve.open(self.shelf)
        #self.flows = {}
        self.p = pcapObj
        self.states = flow_state_manager()
        self.outdir = ""
        self.fname = []
        self.plugins = []
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.p.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type %s not supported: " % datalink)
        
    def __del__(self):
        # take care of some cleanup
        # delete shelf file
        # os.unlink(self.shelf)
        pass

    def registerPlugin(self, cb):
        """
        cb is a function that takes an instance of flow_state as an arg
        """
        self.plugins.append(cb)

    def packetHandler(self, hdr, data):
        try:
            pkt = self.decoder.decode(data)
        except:
            return
        try:
            proto = pkt.child().child().protocol
            shost = pkt.child().get_ip_src()
            dhost = pkt.child().get_ip_dst()
        except: 
            return

        if proto == socket.IPPROTO_TCP:
            self.process_tcp(pkt, shost, dhost)

    def process_ip(self, hdr, data):
        pass

    def process_tcp(self, pkt, src, dst):
        tcp = pkt.child().child()
        ip = pkt.child()
        this_flow = flow()
        this_flow.src = src
        this_flow.dst = dst
        this_flow.sport = tcp.get_th_sport()
        this_flow.dport = tcp.get_th_dport()
        if ip.get_ip_len() == ip.get_header_size() + tcp.get_header_size():
            # no data, return
            return
        self.store_packet(this_flow, tcp)
        
    def store_packet(self, flow, tcp):
        bytes_per_flow = 100000000
        seq = tcp.get_th_seq()
        data = tcp.child().get_buffer_as_string()
        if len(data) <= 0 :
            # no data, move along
            return
        length = len(data)
        state = self.states.find_flow_state(flow)
        if state is None:
            #print "state not found, creating new"
            state = self.states.create_state(flow, seq)
            state.open()
            #else:
            #print "state found"

        if state.flags&FLOW_FINISHED:
            # print "flow finished: %s" % state.flow
            # TODO: Open a new state??
            if tcp.get_SYN():
                print "new flow on prior state: %s" % state.flow
            state.close()
            return

        if tcp.get_FIN() or tcp.get_RST():
            # conection finished
            # close the file
            # print "got RST or FIN"
            state.flags |= FLOW_FINISHED
            state.fp.flush()
            state.close()
            return


        offset = seq - state.isn
        if offset < 0:
            # seq < isn, drop it
            # print "bad seq number"
            return 

        if bytes_per_flow and (offset > bytes_per_flow):
            # too many bytes for this flow, drop it
            #print "too many bytes for flow, dropping packet"
            state.flags |= FLOW_FINISHED
            return

        if bytes_per_flow and (offset + length > bytes_per_flow):
            # long enough, mark this flow finished
            #print "flow marked finished due to length"
            state.flags |= FLOW_FINISHED
            length = bytes_per_flow - offset

        try:
            state.open()
        except fileHandleError:
            self.states.closeFiles()
            state.open()
        state.writeData(data)
    
    def start(self):
        while 1:
            try:
                hdr, data = self.p.next()
                self.packetHandler(hdr, data)
            except PcapError:
                #self.states.closeFiles()
                return
            except:
                traceback.print_exc(file=sys.stdout)
        print "finished"

    def setFilter(self, filter):
        self.p.setfilter(filter)

    def setOutdir(self, dir):
        self.outdir = dir
        self.states.setOutdir(dir)
        if not os.path.exists(self.outdir):
            os.mkdir(self.outdir)

    def setOutput(self, file):
        self.outfile = file

    def dump_extract(self, options):
        for s in self.states.flow_hash.values():
            for func in self.plugins:
                func(s, self.states)
                


    def writeResults(self):
        """TODO: I would like to implement some sort of summarization
        of the data files that were written during the run...
        """
        pass

if __name__ == "__main__":
    from honeysnap import gzToPipe
    import sys
    f = sys.argv[1]
    gz = gzToPipe(f, "/tmp/fifo")
    gz.run()
    pcapObj = open_offline("/tmp/fifo")
    tflow = tcpFlow(pcapObj)
    tflow.setFilter("not port 445")
    tflow.start()

