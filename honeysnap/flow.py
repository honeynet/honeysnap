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

from util import ipnum

HASH_SIZE=1009
FLOW_FINISHED=(1 << 0)
FLOW_FILE_EXISTS=(1 << 1)

def reverse(f):
    """
    f should be a flow instance.
    Returns a flow instance of the reverse flow.
    """
    nf = flow()
    nf.dst = f.src
    nf.src = f.dst

    nf.dport = f.sport
    nf.sport = f.dport
    return nf

class flow:
    def __init__(self):
        self.src = None
        self.dst = None
        self.sport = None
        self.dport = None

    def __eq__(self, other):
        return self.sport==other.sport and self.dport==other.dport and self.src==other.src and self.dst==other.dst

    def __ne__(self, other):
        return self.sport!=other.sport or self.dport!=other.dport or self.src!=other.src or self.dst!=other.dst

    def __repr__(self):
        return "%s.%s-%s.%s" % (self.src, self.sport, self.dst, self.dport)

    
    
class flow_state:
    
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
        self.fname = []
        self.decoded = None

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

    def fhash(self, flow):
        hash =  (((flow.sport & 0xff) | ((flow.dport & 0xff) << 8) | ((ipnum(flow.src) & 0xff) << 16) | ((ipnum(flow.dst) & 0xff) << 24) ) % HASH_SIZE)
        return str(hash)

    def create_state(self, flow, isn):
        new_state = flow_state()
        new_state.flow = flow
        new_state.isn = isn
        new_state.last_access = self.current_time+1
        self.current_time +=1
        index = self.fhash(new_state.flow)
        if index in self.flow_hash:
            tmp = self.flow_hash[index]
            new_state.next = tmp
            self.flow_hash[index] = new_state
        else:
            self.flow_hash[index] = new_state
        return new_state

    
    def find_flow_state(self, flow):
        index = self.fhash(flow)
        #print "index: " + str(index)
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

