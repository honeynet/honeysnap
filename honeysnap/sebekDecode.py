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

"""
v2
struct sbk_h{
  uint32_t  magic       __attribute__((packed)) ; I
  uint16_t  ver         __attribute__((packed)) ; H
  uint16_t  type        __attribute__((packed)) ; H
  uint32_t  counter     __attribute__((packed)) ; I
  uint32_t  time_sec    __attribute__((packed)) ; I
  uint32_t  time_usec   __attribute__((packed)) ; I
  uint32_t  pid         __attribute__((packed)) ; I
  uint32_t  uid         __attribute__((packed)) ; I
  uint32_t  fd          __attribute__((packed)) ; I
  char       com[12]     __attribute__((packed)) ; 12s
  uint32_t  length      __attribute__((packed)) ; I
};

v3
struct sbk_h{
  uint32_t  magic       __attribute__((packed)) ; I
  uint16_t  ver         __attribute__((packed)) ; H
  uint16_t  type        __attribute__((packed)) ; H
  uint32_t  counter     __attribute__((packed)) ; I
  uint32_t  time_sec    __attribute__((packed)) ; I
  uint32_t  time_usec   __attribute__((packed)) ; I
  uint32_t  parent_pid  __attribute__((packed)) ; I
  uint32_t  pid         __attribute__((packed)) ; I
  uint32_t  uid         __attribute__((packed)) ; I
  uint32_t  fd          __attribute__((packed)) ; I
  uint32_t  inode       __attribute__((packed)) ; I
  char      com[12]     __attribute__((packed)) ; 12s
  uint32_t  length      __attribute__((packed)) ; I
};
"""

import struct, dpkt, time, re
import base
from singletonmixin import HoneysnapSingleton
import pcap
from socket import inet_ntoa

sbk2 = "!IHHIIIIII12sI"
sbk3 = "!IHHIIIIIIII12sI"
size2 = struct.calcsize(sbk2)
size3 = struct.calcsize(sbk3)

# mapping of control characters
controlmap = {"\x1b[A":"[U-ARROW]",
            "\x1b[B":"[D-ARROW]",
            "\x1b[C":"[R-ARROW]",
            "\x1b[D":"[L-ARROW]",
            "\x1b[3~":"[DEL]",
            "\x1b[5~":"[PAGE-U]",
            "\x1b[6~":"[PAGE-D]",
            "\x7f":"[BS]",
            "\x1b":"[ESC]"}

controllist = ["\x1b[A", "\x1b[B","\x1b[C", "\x1b[D","\x1b[3~","\x1b[5~","\x1b[6~","\x7f","\x1b"]
# regex for other nonascii values
nonascii = re.compile("[\x80-\xFF]")

tf = lambda x: time.asctime(time.localtime(x))

class sebekDecode(base.Base):
    
    def __init__(self):
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.p = pcap.pcap(options["tmpf"], promisc=False)
        self.p.setfilter("udp port 1101")
        self.log = {}
        
    def packetHandler(self, ts, pkt, payload):
        #print pkt.udp.ulen
        if len(payload) > 5:
            magic, version = struct.unpack("!IH", payload[0:6])
            if version == 1:
                sbk = sbk2
                size = size2
            elif version == 3:
                sbk = sbk3
                size = size3
            else:
                return
            #print magic, version
        else:
            return
        sbkhdr = payload[0:size]
        rest = payload[size:]
        magic, version, typ, counter, t, tu, pid, uid, fd, com, length = struct.unpack(sbk, sbkhdr)
        ip = inet_ntoa(pkt.src)
        if typ == 0 and length < 100:
            self.keystrokes(t, ip, pid, fd, uid, com, rest)
    
    def keystrokes(self, t, ip, pid, fd, uid, com, data):
        """
        [$datetime  $addr $pid $com_str $uid_str]$log
        """
        k = " ".join([ip, str(pid), str(fd)])
        com = com.replace("\00", "")
        if k not in self.log:
            self.log[k] = {"data":data, "uid":{uid:1}, "com":{com:1}}
        else:
            self.log[k]["data"] += data
            self.log[k]["uid"][uid] = 1
            self.log[k]["com"][com] = 1
            
        if "\r" in data or "\n" in data:
            uids = "/".join([str(i) for i in self.log[k]["uid"].keys()])
            coms = "/".join([str(i) for i in self.log[k]["com"].keys()])
            # strip out junk
            d = self.log[k]["data"]
            for i in controllist:
                # change control characters to something useful
                d = d.replace(i, controlmap[i])
                # strip out nonascii junk
                d = nonascii.sub("", d)
            print "[%s %s %s %s] %s" % (tf(t), k, uids, coms, d)
            del self.log[k]
        
    def run(self):
        # since we set a filter on pcap, all the
        # packets we pull should be handled
        for ts, pkt in self.p:
            ip = dpkt.ip.IP(pkt[self.p.dloff:])
            # workaround for broken sebek packets
            payload = pkt[self.p.dloff+20+8:]  #frame+iphdr+udphdr
            try:
                self.packetHandler(ts, ip, payload)
            except Exception, e:
                print "sebekDecode caught error:"
                print e
                print dpkt.dpkt.hexdump(ip.udp.data)
                continue

        
