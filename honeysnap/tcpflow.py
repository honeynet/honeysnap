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

NUM_RESERVED_FDS=25
HASH_SIZE=1009
FLOW_FINISHED=(1 << 0)
FLOW_FILE_EXISTS=(1 << 1)

def ipnum(ip) :
    "Return a numeric address for an ip string"
    v = 0L
    for x in ip.split(".") :
        v = (v << 8) | int(x);
    return v

class flow:
    def __init__(self):
        self.src = None
        self.dst = None
        self.sport = None
        self.dport = None
    
class flow_state:
    
    fname = []

    def __init__(self):
        self.next = None # link to next flow state
        self.flow = None # Description of the flow
        self.isn = None  # Initial Seq Number
        self.fp = None   # file pointer for this flows data
        self.pos = 0
        self.flags = 0
        self.last_access = 0 # time of last access
        self.size  = 0
        self.dport = 0
        self.lname = ""
        self.filetype = ""
        self.realname = ""
        self.data = []

    def __cmp__(self, other):
        # to facilitate sorting a list of states by last_access
        return cmp(self.last_access, other.last_access)


class flow_state_manager:

    def __init__(self):
        self.current_time = 0
        self.flow_hash = {}
        self.curent_time = 0
        self.outdir = None
        
    def setOutdir(self, outdir):
        self.outdir = outdir

    def hash_flow(self, flow):
        hash =  (((flow.sport & 0xff) | ((flow.dport & 0xff) << 8) | ((ipnum(flow.src) & 0xff) << 16) | ((ipnum(flow.dst) & 0xff) << 24) ) % HASH_SIZE)
        return hash

    def create_state(self, flow, isn):
        new_state = flow_state()
        index = flow
        if index in self.flow_hash:
            new_state.next = self.flow_hash[index]
        self.flow_hash[index] = new_state

        new_state.flow = flow
        new_state.isn = isn
        new_state.last_access = self.current_time+1
        self.current_time +=1
        return new_state
    
    def find_flow_state(self, flow):
        index = flow
        if index in self.flow_hash:
            state = self.flow_hash[index]
        else:
            return None
        if state.flow == flow:
            state.last_access = self.current_time+1
            self.current_time +=1
            return state
        else:
            while state.next is not None:
                #print "looking at state.next"
                if state.next == state:
                    #print "state.next = state, thats bad"
                    return None
                state = state.next
                if state.flow == flow:
                    state.last_access = self.current_time+1
                    self.current_time +=1
                    return state
        return None

    def flow_filename(self, flow):
        """
        filename should be:
        "%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d"
        """
        name = "%s/%s.%s-%s.%s" % (self.outdir, flow.src, flow.sport, flow.dst, flow.dport)
        return name

class tcpFlow:
    #fname = []
    #fhash = {}

    def __init__(self, pcapObj):
        # create a tmp file to hold the shelve
        self.shelf = tempfile.mkstemp()[1]
        os.unlink(self.shelf)
        self.flows = shelve.open(self.shelf)
        self.p = pcapObj
        self.states = flow_state_manager()
        self.outdir = ""
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.p.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type mkstemp(not supported: " % datalink)
        
    def destroy(self):
        # take care of some cleanup
        # delete shelf file
        pass

    def flow_filename(self, flow):
        """
        filename should be:
        "%03d.%03d.%03d.%03d.%0tmp59apTB5d-%03d.%03d.%03d.%03d.%05d"
        """
        name = "%s/%s.%s-%s.%s" % (self.outdir, flow.src, flow.sport, flow.dst, flow.dport)
        return name
    
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
        bytes_per_flow = 1000000
        length = len(data)
        state = self.states.find_flow_state(flow)
        if state is None:
            #print "state not found, creating new"
            state = self.states.create_state(flow, seq)

        if state.flags&FLOW_FINISHED:
            print "flow finished"
            return

        offset = seq - state.isn
        if offset < 0:
            # seq < isn, drop it
	    print "bad seq number"
            return

        if bytes_per_flow and (offset > bytes_per_flow):
            # too many bytes for this flow, drop it
            print "too many bytes for flow, dropping packet"
            return

        if bytes_per_flow and (offset + length > bytes_per_flow):
            # long enough, mark this flow finished
            print "flow marked finished due to length"
            state.flags |= FLOW_FINISHED
            length = bytes_per_flow - offset

        filename = self.flow_filename(state.flow)
        if self.flows.has_key(filename):
            #print "existing flow file %s" % filename
            #self.flows[filename].data.append(data)
            #print "added %s data to file\n" % len(data)
	    state.data.append(data)
            state.size = state.size + len(data)
        else:
            #print "new flow file %s" % filename
            state.data.append(data)
            state.size = len(data)
            #print "added %s data to file\n" % len(data)
            state.dport = flow.dport
            self.flows[filename] = state
        
        # sync the shelf, just to be sure
        self.flows.sync()
    
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

    def idflows(self):
        for fstr in self.flows.keys():
            t = ram()
            stream = ""
            for line in self.flows[fstr].data:
                stream = stream + line
                
            filetype = t.filetype(stream)
            self.flows[fstr].filetype = filetype  

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
        for e in self.flows.keys():
            if self.flows[e].realname:
                if self.flows[e].dport == 80:
                    type = "http-extract/"
                elif self.flows[e].dport == 20:
                    type = "ftp-extract/"
                elif self.flows[e].dport == 6667:
                    type = "irc-extract/"
                elif self.flows[e].dport == 25:
                    type = "smtp-extract/"

                mfp = open(options["output_data_directory"] + "/"+ type + self.flows[e].realname,"a")
            else:
                mfp = open(e,"a")

            for y in self.flows[e].data:
                print "writing data to: %s" % e
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

