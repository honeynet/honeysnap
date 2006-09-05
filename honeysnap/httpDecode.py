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

import dpkt
from flow import reverse as freverse

class httpDecode:
    
    def __init__(self):
        self.statemgr = None
        
    def decode(self, state, statemgr):
        """
        Takes an instance of flow.flow_state, and an instance of
        flow.flow_state_manager
        """
        self.statemgr = statemgr
        # The following could be a problem for files having size in the 10s or
        # 100s of MB, I dunno:
        parsed = False
        d = "".join(state.data)
        r = None
        f = state.flow
        print '%s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
        if not parsed:
            try:
                print 'response:'
                r = dpkt.http.Response(d)
                #print `r`
                #print 'headers: ', r.headers
                #print 'version: ', r.version
                #print 'status: ', r.status
                #print 'reason: ', r.reason
                print 'len(body): ', len(r.body)
                print "\n"
                parsed = True
            except:
                print "response failed decode\n"
                #pass
            if r:
                state.decoded = r
                self._renameFlow(r, state)

        if not parsed:
            try:
                # The following line does essentially all the work:
                r = dpkt.http.Request(d)
                state.decoded = r
                print 'request:'
                #print 'method: ', r.method
                print 'uri:    ', r.uri
                print "\n"
                parsed = True
            except:
                print "request failed decode\n"
                #pass
            if r:
                state.decoded = r

    def _renameFlow(self, r, state):
        print "******************"
        rflow = freverse(state.flow)
        print rflow
        rstate = self.statemgr.find_flow_state(rflow)
        print rstate
        if rstate is not None:
            if rstate.decoded:
                r1 = rstate.decoded
                rstate.realname = r1.uri.rsplit("/", 1)[-1]
                print rstate.realname
        else:
            print "reverse state not found"
        print "#######################\n"
            
        
