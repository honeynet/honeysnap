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

import dpkt
from flow import reverse as freverse
from singletonmixin import HoneysnapSingleton
import cStringIO
import os
from util import findName, renameFile
from flowIdentify import flowIdentify
from base import Base
import urllib

def parse_headers(f):
    """Return dict of HTTP headers parsed from a file object."""
    d = {}
    while 1:
        line = f.readline()
        if not line:
            raise dpkt.NeedData('premature end of headers')
        line = line.strip()
        if not line:
            break
        l = line.split(':', 1)
        if not len(l) == 2:
            raise dpkt.UnpackError('invalid header: %r' % line)
        l[0] = l[0] + ':'
        k = l[0][:-1].lower()
        d[k] = len(l) != 1 and l[1] or ''
    return d

def parse_body(f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict."""
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        l = []
        found_end = False
        while 1:
            try:
                sz = f.readline().split(None, 1)[0]
            except IndexError:
                raise dpkt.UnpackError('missing chunk size')
            n = int(sz, 16)
            if n == 0:
                found_end = True
            buf = f.read(n)
            if f.readline().strip():
                break
            if n and len(buf) == n:
                l.append(buf)
            else:
                break
        if not found_end:
            raise dpkt.NeedData('premature end of chunked body')
        body = ''.join(l)
    elif 'content-length' in headers:
        n = int(headers['content-length'])
        body = f.read(n)
        if len(body) != n:
            raise dpkt.NeedData('short body (missing %d bytes)' % (n - len(body)))
    elif 'content-type' in headers:
        body = f.read()
    else:
        # XXX - need to handle HTTP/0.9
        body = ''
    return body

class myMessage(dpkt.http.Message):
    """Hypertext Transfer Protocol headers + body."""
    __metaclass__ = type
    __hdr_defaults__ = {}
    headers = None
    body = None

    def __init__(self, *args, **kwargs):
        super(myMessage, self).__init__()

    def unpack(self, buf):
        f = cStringIO.StringIO(buf)
        # Parse headers
        self.headers = parse_headers(f)
        # Parse body
        self.body = parse_body(f, self.headers)
        # Save the rest
        self.data = f.read()

class httpDecode(Base):

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
        hs = HoneysnapSingleton.getInstance()
        Base.__init__(self) 
        self.options = hs.getOptions()
        self.statemgr = None
        self.id = flowIdentify()

    def determineType(self, data):
        """
        Data should be a list of the data as obtained via file.readlines()
        Attempts to figure out if this data represents a request
        or a response.
        """
        line = data[0]
        #print "determineType:line %s" % line
        l = line.strip().split()
        # is it a request?
        if len(l) == 3 and l[0] in self.__methods and l[2].startswith(self.__proto):
            return('request', line)

        # is it a response?
        if len(l) >= 2 and l[0].startswith(self.__proto) and l[1].isdigit():
            return('response', line)

        #print "determineType:unknown type, probably binary "
        return None, None


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
        #print "decode:state ", state.fname
        if len(d) == 0:
            return
        t, req = self.determineType(d)
        if (t, req) == (None, None):
            # binary data
            return
        d = "".join(d)
        state.close()
        r = None
        f = state.flow
        #print 'decode: %s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
        if t =='response':
            try:
                #print 'decode:response:'
                #print 'decode:%s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
                r = dpkt.http.Response(d)
                r.request = req
                if not getattr(r, "data"):
                    r.data = None
                state.decoded = r
                #print 'decode: %s' % `r`
                #print 'decode:headers: ', r.headers
                #print 'decode:version: ', r.version
                #print 'decode:status: ', r.status
                #print 'decode:reason: ', r.reason
                #print 'decode:len(body): ', len(r.body)
                #print "\n"
            except dpkt.Error:
                try:
                    state.open(flag="rb")
                    l = state.fp.readline()
                    headers = parse_headers(state.fp)
                    r = myMessage()
                    r.headers = headers
                    r.body = state.fp.readlines()
                    r.data = None
                    r.request = req
                    state.decoded = r
                    state.close()
                    #print 'decode:headers %s' % headers
                except dpkt.Error:
                    print "response failed to decode: %s " % state.fname
                    pass

        if t == 'request':
            try:
                #print 'decode:request:'
                #print 'decode: %s.%s-%s.%s' % (f.src, f.sport, f.dst, f.dport)
                # The following line does essentially all the work:
                r = dpkt.http.Request(d)
                state.decoded = r
                r.request = req
                if not getattr(r, "data"):
                    r.data = None
                #print 'decode:method: ', r.method
                #print 'decode:uri:    ', r.uri
                #print "\n"
            except dpkt.Error:
                try:
                    state.open(flag="rb")
                    l = state.fp.readline()
                    headers = parse_headers(state.fp)
                    r = myMessage()
                    r.headers = headers
                    r.body = state.fp.readlines()
                    r.request = req
                    r.data = None
                    state.decoded = r
                    state.close()
                    #print 'decode:headers ', headers
                except dpkt.Error:
                    print "request failed to decode: %s " % state.fname
                    pass

        if r:
            state.decoded = r
        else:
            return
        if t is not None:
            self.extractHeaders(state, d)
        rs = self.statemgr.find_flow_state(freverse(state.flow)) 
        if rs.decoded:      
            self._renameFlow(state, t)
        else:                                    
            self.decode(rs, self.statemgr)


    def _renameFlow(self, state, t):
        """state is a honeysnap.flow.flow_state object, t = response or request"""
        #print "_renameFlow:state", state.fname
        rflow = freverse(state.flow)   
        #print '_renameFlow:rflow   ', rflow
        rs = self.statemgr.find_flow_state(rflow)
        if rs is not None:
            if rs.decoded is not None and state.decoded is not None:
                #print "Both halves decoded"
                r1 = rs.decoded

                if t == 'request':
                    try:
                        url = urllib.splitquery(state.decoded.uri)[0]
                        realname = url.rsplit("/", 1)[-1] 
                    except AttributeError:
                        realname = 'index.html'
                    try: 
                        url = state.decoded.headers['host'] + url  
                    except KeyError:
                        pass
                    # reverse flows to get right sense for file renaming    
                    temp = rs
                    rs = state
                    state = temp
                if t == 'response':
                    url = urllib.splitquery(r1.uri)[0]
                    realname = url.rsplit("/", 1)[-1] 
                    try:
                        url = r1.headers['host'] + url
                    except KeyError:
                        # probably something like a CONNECT
                        pass
                if realname == '' or realname == '/' or not realname:
                    realname = 'index.html' 
                fn = renameFile(state, realname)
                id, m5 = self.id.identify(state)
                if 'outgoing' in fn:
                    self.doOutput("Requested %s\n" % url)
                    self.doOutput("\tfile: %s, filetype: %s, md5 sum: %s\n" %(fn,id,m5))
                elif self.options['print_http_served'] == 'YES': 
                    self.doOutput("Served %s\n" % url)
                    self.doOutput("\tfile: %s, filetype: %s, md5 sum: %s\n" %(fn,id,m5))                         

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
            except dpkt.Error:
                request = ""
            try:
                data = state.decoded.data
            except dpkt.Error:
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



