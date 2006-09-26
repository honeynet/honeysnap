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

import struct, dpkt, dnet, time
import base
from singletonmixin import HoneysnapSingleton
import pcap

sbk2 = "!IHHIIIIII12sI"
sbk3 = "!IHHIIIIIIII12sI"
size2 = struct.calcsize(sbk2)
size3 = struct.calcsize(sbk3)

class sebekDecode(base.Base):
    
    def __init__(self):
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.p = pcap.pcap(options["tmpf"], promisc=False)
        self.p.setfilter("udp port 1101")
        self.log = {}
        
    def packetHandler(self, ts, pkt):
        #print pkt.udp.ulen
##        import pdb
##        pdb.set_trace()
        if len(pkt.udp.data) > 5:
            magic, version = struct.unpack("!IH", pkt.udp.data[0:6])
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
        data = pkt.udp.data[0:size]
        rest = pkt.udp.data[size:]
        magic, version, typ, counter, t, tu, pid, uid, fd, com, length = struct.unpack(sbk, data)
        ip = str(dnet.addr(pkt.src))
        if typ == 0 and length < 100:
            self.keystrokes(t, ip, pid, fd, uid, com, rest)
    
    def keystrokes(self, t, ip, pid, fd, uid, com, data):
        """
        [$datetime  $addr $pid $com_str $uid_str]$log
        """
        k = "-".join([ip, str(pid), str(fd)])
        if k not in self.log:
            self.log[k] = {"data":data, "uid":{uid:1}, "com":{com:1}}
        else:
            self.log[k]["data"] += data
            self.log[k]["uid"][uid] = 1
            self.log[k]["com"][com] = 1
            
        if "\r" in data or "\n" in data:
            print "%s %s %s %s %s" % (time.asctime(time.localtime(t)), k, uid, com, self.log[k]["data"])
            del self.log[k]


        
    def run(self):
        for ts, pkt in self.p:
            ip = dpkt.ip.IP(pkt[self.p.dloff:])
            try:
                self.packetHandler(ts, ip)
            except Exception, e:
                print "sebekDecode caught error:"
                print e
                print dpkt.dpkt.hexdump(ip.udp.data)
                continue

        
