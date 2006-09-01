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

import os, sys, shelve, tempfile, re
import impacket
import socket
import pcapy
from pcapy import *
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import traceback
from flow import flow, flow_state, flow_state_manager

FLOW_FINISHED=(1 << 0)
FLOW_FILE_EXISTS=(1 << 1)

class tcpFlow:

    def __init__(self, pcapObj):
        # create a tmp file to hold the shelve
        self.shelf = tempfile.mkstemp()[1]
        os.unlink(self.shelf)
        self.flows = shelve.open(self.shelf)
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
            raise Exception("Datalink type mkstemp(not supported: " % datalink)
        
    def __del__(self):
        # take care of some cleanup
        # delete shelf file
        os.unlink(self.shelf)

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
        this_flow = flow()
        this_flow.src = src
        this_flow.dst = dst
        this_flow.sport = tcp.get_th_sport()
        this_flow.dport = tcp.get_th_dport()
        seq = tcp.get_th_seq()
        data = tcp.child().get_buffer_as_string()
        self.store_packet(this_flow, data, seq)
        
    def store_packet(self, flow, data, seq):
        bytes_per_flow = 100000000
        length = len(data)
        state = self.states.find_flow_state(flow)
        if state is None:
            #print "state not found, creating new"
            state = self.states.create_state(flow, seq)
            #else:
            #print "state found"

        if state.flags&FLOW_FINISHED:
            #print "flow finished"
            return

        offset = seq - state.isn
        if offset < 0:
            # seq < isn, drop it
            #print "bad seq number"
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

        filename = self.states.flow_filename(state.flow)
        if self.flows.has_key(filename):
            #print "existing flow file %s" % filename
            s = self.flows[filename]
            s.data.append(data)
            s.size +=  len(data)
            self.flows[filename] = s
            #state.data.append(data)
            #state.size = state.size + len(data)
            #print "added %s data to file %s size: %s\n" % (len(data), filename, s.size)
        else:
            #print "new flow file %s" % filename
            state.data.append(data)
            state.size = len(data)
            #print "added %s data to file\n" % len(data)
            state.dport = flow.dport
            self.flows[filename] = state
            #print "added %s data to NEW file %s size: %s\n" % (len(data), filename, state.size)
        
        # sync the shelf, just to be sure
        #self.flows.sync()
    
    def start(self):
        while 1:
            try:
                hdr, data = self.p.next()
                self.packetHandler(hdr, data)
            except PcapError:
                return
            except:
                traceback.print_exc(file=sys.stdout)

        """
        try:
            self.p.dispatch(-1, self.packetHandler)
        except:
            print "Exception in user code:"
            print '-'*60
            traceback.print_exc(file=sys.stdout)
            print '-'*60
        """
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

    def getnames(self):
        for z in self.flows.keys():
            if self.flows[z].dport == 80:
                #hreg = re.compile("^M")
                for line in self.flows[z].data:
                    line = re.sub("^M","",line)
                    match = re.search("^GET ",line)
                    if(match):
                        gline = line.split()
                        rn = re.sub(".*/+","",gline[1])
                        self.flows[self.reverseflow(z)].realname = rn
                        self.flows[self.reverseflow(z)].dport = self.flows[z].dport
                        self.adjustdataflow(self.reverseflow(z))

    def adjustdataflow(self,flow):
        i = 0
        tstring = ""

        for line in self.flows[flow].data:
            tstring = tstring + line
            
        #match = re.sub("\r\n\r\n","",tstring)
        match = string.find(tstring,"\r\n\r\n")
        if(match):
            match = match+4
            self.flows[flow].data = []
            self.flows[flow].data.append(tstring[match:len(tstring)])
            self.idflows(de)
            print "extracted file with name of: " + self.flows[flow].realname + " (" + self.flows[flow].filetype + ")"
            return

        i = i + 1

    def reverseflow(self, name):
        print name
        tmp = name.rsplit("/")
        tmp.reverse()
        print tmp
        line = tmp[0].rsplit("-")
        print line
        tmp[0] = "%s-%s" % (line[1], line[0])
        tmp.reverse()
        tstr = "/".join("%s" % k for k in tmp)
        print "tstr: " + tstr
        return tstr 

    def dump_extract(self, options):
        type = ""
        for f, e in self.flows.items():
            for func in self.plugins:
                func(e, self.states)
            if e.realname:
                if e.dport == 80:
                    type = "http-extract/"
                elif e.dport == 20:
                    type = "ftp-extract/"
                elif e.dport == 6667:
                    type = "irc-extract/"
                elif e.dport == 25:
                    type = "smtp-extract/"
                
                filename = options["output_data_directory"]+"/"+type+e.realname+".1"
                if os.path.exists(filename):
                    name, ext = filename.rsplit(".", 1)
                    ext = int(ext)+1
                    filename = filename +"."+str(ext)
                mfp = open(filename,"wb")
            else:
                filename = f+".1"
                if os.path.exists(filename):
                    filename, ext = filename.rsplit(".", 1)
                    ext = int(ext)+1
                    filename = filename +"."+str(ext)
                mfp = open(filename,"a")

            for y in e.data:
                #print "writing data to: %s" % e
                mfp.write(y)

            mfp.flush()
            mfp.close()


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

