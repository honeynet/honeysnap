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
import cStringIO
import os

class httpDecode(object):

    # this part stolen from dpkt.  Thanks Dug!
    __methods = dict.fromkeys((
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
        ))
    __proto = 'HTTP'
    
    __msgtypes = ['response', 'request']
    
    def __init__(self):
        self.statemgr = None
        
    def determineType(self, data):
        """
        Data should be a list of the data as obtained via file.readlines()
        Attempts to figure out if this data represents a request
        or a response.
        """
        line = data[0]
        #print line
        l = line.strip().split()
        # is it a request?
        if len(l) == 3 and l[0] in self.__methods and l[2].startswith(self.__proto):
            return('request', line)
            
        # is it a response?
        if len(l) >= 2 and l[0].startswith(self.__proto) and l[1].isdigit():
            return('response', line)
            
        return None, line
        
        
    def decode(self, state, statemgr):
        """
        Takes an instance of flow.flow_state, and an instance of
        flow.flow_state_manager
        """
        self.statemgr = statemgr
        # The following could be a problem for files having size in the 10s or
        # 100s of MB, I dunno:
        #d = "".join(state.data)
        state.close()
        state.open(flag="rb")
        d = state.fp.readlines()
        t, req = self.determineType(d)
        d = "".join(d)
        state.close()
        r = None
        f = state.flow
        #print '%s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
        if t =='response':
            try:
                # print 'response:'
                # print '%s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
                r = dpkt.http.Response(d)
                r.request = req
                if not getattr(r, "data"):
                    r.data = None
                state.decoded = r
                #print `r`
                #print 'headers: ', r.headers
                #print 'version: ', r.version
                #print 'status: ', r.status
                #print 'reason: ', r.reason
                # print 'len(body): ', len(r.body)
                # print "\n"
                parsed = True
            except:
                try:
                    state.open(flag="rb")
                    l = state.fp.readline()
                    headers = dpkt.http.parse_headers(state.fp)
                    r = dpkt.http.Message()
                    r.headers = headers
                    r.body = fp.readlines()
                    r.data = None
                    r.request = req
                    state.decoded = r
                    state.close()
                    #print headers
                except:
                    #print "response failed decode: %s " % state.fname
                    pass

            if r:
                state.decoded = r
            self._renameFlow(state)

        if t == 'request':
            try:
                #print 'request:'
                #print '%s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
                # The following line does essentially all the work:
                r = dpkt.http.Request(d)
                state.decoded = r                
                r.request = req
                if not getattr(r, "data"):
                    r.data = None
                #print 'method: ', r.method
                #print 'uri:    ', r.uri
                #print "\n"
                parsed = True
            except:
                try:
                    state.open(flag="rb")
                    l = state.fp.readline()
                    headers = dpkt.http.parse_headers(state.fp)                    
                    r = dpkt.http.Message()
                    r.headers = headers
                    r.body = fp.readlines()
                    r.request = req
                    r.data = None
                    state.decoded = r
                    state.close()
                    #print headers
                except:
                    #print "request failed decode: %s " % state.fname
                    pass
                
            if r:
                state.decoded = r
        if t is not None:
            self.extractHeaders(state, d)

    def _renameFlow(self, state):
        #print "******************"
        rflow = freverse(state.flow)
        #print rflow
        rs = self.statemgr.find_flow_state(rflow)
        if rs is not None:
            if rs.decoded is not None:
                r1 = rs.decoded
                realname = r1.uri.rsplit("/", 1)[-1]
                #print realname
                # make sure filename is't too long
                if len(realname) > 15:
                    realname = realname[0:15]
                # rename the file
                state.realname = realname
                newfn = self.findName(state.fname, realname)
                # print "renaming %s to %s" %(state.fname, newfn)
                os.rename(state.fname, newfn)
                state.fname = newfn
        
    def findName(self, filename, realname):
        head, tail = os.path.split(filename)
        newfn = head+'/'+realname+".1"
        while 1:
            if os.path.exists(newfn):
                newfn, ext = newfn.rsplit(".", 1)
                ext = int(ext)+1
                newfn = newfn + "." +str(ext)
            else:
                return newfn
    
    def extractHeaders(self, state, d):
        """
        Pull the headers and body off the data,
        drop them into the filename.hdr, filename.body files
        Write remaining data back to original file
        Header parsing stolen from dpkt.http
        """
        headers = None
        data = None
        body = None
        request = ""
        f = cStringIO.StringIO(d)
        if state.decoded is not None:
            # this request was successfully decoded
            # so the decoded object will contain all the headers
            # and the detached data
            headers = {}
            headers = state.decoded.headers
            body = state.decoded.body
            try:
                request = state.decoded.request
            except:
                request = ""
            try:
                data = state.decoded.data
            except:
                data = None
            
        else:
            # dpkt.http failed to decode
            f = cStringIO.StringIO(d)
            headers = {}
            # grab whatever headers we can
            while 1:
                line = f.readline()
                if not line:
                    return
                request = line
                line = line.strip()
                if not line:
                    break
                l = line.split(None, 1)
                if not l[0].endswith(':'):
                    break
                k = l[0][:-1].lower()
                headers[k] = len(l) != 1 and l[1] or ''
            # this state is somehow broken, or dpkt would have decoded it
            # we'll just put the rest of the data into a file
            data = f.readlines()
            data = "".join(data)
            body = None
            
        # write headers, body, data to files
        if headers is not None:
            base = state.fname
            base += ".hdr"
            fp = open(base, "wb")
            rf = freverse(state.flow)
            s = "reverse flow: %s\n" % rf.__repr__()
            fp.write(s)
            fp.write(request)
            for k,v in headers.items():
                line = k + " : " + v + "\n"
                fp.write(line)
            fp.close()
        if body is not None:
            base = state.fname
            #base += ".body"
            fp = open(base, "wb")
            if isinstance(body, type([])):
                body = "".join(body)
            fp.write(body)
            fp.close()
        if data is not None:
            base = state.fname
            base += ".data"
            fp = open(base, "wb")
            if isinstance(data, type([])):
                data = "".join(data)
            fp.write(data)
            fp.close()
        
