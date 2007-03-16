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

Sebek data structure:

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

import sys
import struct
import time
import re
from socket import inet_ntoa
import dpkt
import pcap                 

from honeysnap.singletonmixin import HoneysnapSingleton
from honeysnap.model.model import *

sbk2 = "!IHHIIIIII12sI"
sbk3 = "!IHHIIIIIIII12sI"
size2 = struct.calcsize(sbk2)
size3 = struct.calcsize(sbk3)
       
SBK_READ  = 0
SBK_WRITE = 1
SBK_SOCK  = 2
SBK_OPEN  = 3

class SebekDecodeError(Exception):
    pass

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
nonascii = re.compile("[^\x20-\x7e]")

class SebekDecode(object):

    def __init__(self, file, filename, hp):
        hs = HoneysnapSingleton.getInstance()
        options = hs.getOptions()
        self.engine = connect_to_db(options['dburi'], options['debug']) 
        self.p = pcap.pcap(file)      
        self.filename = filename
        self.p.setfilter("src host %s and udp dst port %s" % (hp, options["sebek_port"]))
        self.verbose = options['sebek_all_data']
        self.log = {}
        self.session = create_session()
        self.hp = Honeypot.get_or_create(self.session, hp)   

    def unpack_sebek(self, payload):
        """unpack sebek data"""
        if len(payload) > 5:
            magic, version = struct.unpack("!IH", payload[0:6])
            if version == 1:
                size = size2
            elif version == 3:
                size = size3
            else:
                raise SebekDecodeError("Unknown sebek version number")
        else:
            raise SebekDecodeError("Packet too short")
        sbkhdr = payload[0:size]
        rest = payload[size:]
        # next two bits of info not in ver2 sebek data
        parent_pid = 0
        inode = 0     
        if version == 1:
            magic, version, type, counter, t, tu, pid, uid, fd, com, length = struct.unpack(sbk2, sbkhdr)
        else:
            magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, inode, com, length = struct.unpack(sbk3, sbkhdr)  
        return magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest

    def packet_handler(self, ts, payload):
        """ts timestamp, payload = sebek udp data""" 
        try:
            magic, version, type, counter, t, tu, parent_pid, pid, uid, fd, com, inode, length, rest = self.unpack_sebek(payload)
        except SebekDecodeError:
            return           
        if type == SBK_READ:    
            self.sbk_keystrokes(version, t, pid, fd, uid, com, rest, parent_pid, inode) 
        elif type == SBK_WRITE:
            self.sbk_write(version, t, pid, fd, uid, com, rest, parent_pid, inode)
        elif type == SBK_SOCK and self.verbose: 
            self.sbk_sock(version, t, pid, fd, uid, com, rest, parent_pid, inode) 
        elif type == SBK_OPEN and self.verbose:                                                           
            self.sbk_open(version, t, pid, fd, uid, com, rest, parent_pid, inode) 
      
    def sbk_write(self, version, t, pid, fd, uid, com, data, parent_pid, inode):
        """Decode sebek write data. Store data for stdin, stdout and stderr only for now"""
        if version == 1: 
            raise SebekDecodeError("SBK_WRITE in ver 1 data!")
        if fd<3:      
            com = nonascii.sub("", com)
            s = Sebek(version=version, type=SBK_WRITE, timestamp=t, pid=pid, fd=fd, \
                uid=uid, command=com, parent_pid=parent_pid, inode=inode, data=data)
            self.hp.sebek_lines.append(s)
        else:
            # should hex-encode data here or something
            return
        
    def sbk_sock(self, version, t, pid, fd, uid, com, data, parent_pid, inode):
        """Decode sebek socket data"""  
        if version == 1:
            raise SebekDecodeError("SBK_SOCK in ver 1 data!")
        com = nonascii.sub("", com)  
        data = nonascii.sub("", data)
        s = Sebek(version=version, type=SBK_SOCK, timestamp=t, pid=pid, fd=fd, uid=uid, \
            command=com, parent_pid=parent_pid, inode=inode, data=data)
        self.hp.sebek_lines.append(s)
        
    def sbk_open(self, version, t, pid, fd, uid, com, data, parent_pid, inode):
        """Decode sebek file open data"""   
        if version == 1:
            raise SebekDecodeError("SBK_OPEN in ver 1 data")
        com = nonascii.sub("", com)
        data = nonascii.sub("", data)  
        s = Sebek(version=version, type=SBK_OPEN, timestamp=t, pid=pid, fd=fd, uid=uid, \
            command=com, parent_pid=parent_pid, inode=inode, data=data)
        self.hp.sebek_lines.append(s)    

    def sbk_keystrokes(self, version, t, pid, fd, uid, com, data, parent_pid=0, inode=0):
        """
        Extract sebek keystroke/sbk_read data
        """    
        if version == 1 and (parent_pid or inode):
            raise SebekDecodeError("parent_pid or inode in v1 data")
        k = " ".join([str(pid), str(fd)])
        com = com.replace("\00", "")
        if k not in self.log:
            self.log[k] = {"data":data, "uid":{uid:1}, "com":{com:1}, "pid":pid, "fd":fd}
            if version == 3:
                self.log[k]["parent_pid"] = parent_pid
                self.log[k]["inode"] = inode
        else:
            self.log[k]["data"] += data
            self.log[k]["uid"][uid] = 1
            self.log[k]["com"][com] = 1

        if "\r" in data or "\n" in data:
            uids = "/".join([str(i) for i in self.log[k]["uid"].keys()])
            coms = "/".join([str(i) for i in self.log[k]["com"].keys()])
            coms = nonascii.sub("", coms)
            # strip out junk
            d = self.log[k]["data"]
            for i in controllist:
                # change control characters to something useful
                d = d.replace(i, controlmap[i])
                # strip out nonascii junk
                d = nonascii.sub("", d)                
            s = Sebek(version=version, type=SBK_READ, timestamp=t, pid=pid, fd=fd, uid=uid, \
                command=com, parent_pid=parent_pid, inode=inode, data=d) 
            self.hp.sebek_lines.append(s)                                                                                                       
            del self.log[k]

    def run(self):
        # since we set a filter on pcap, all the
        # packets we pull should be handled
        for ts, buf in self.p:
            ip = dpkt.ethernet.Ethernet(buf).data
            # workaround for broken sebek packets
            # udp length and ip length are set incorrectly in v2 and v3 < 3.1
            payload = buf[self.p.dloff+20+8:]  #frame+iphdr+udphdr
            try:
                self.packet_handler(ts, payload)
            except struct.error, e:
                continue  
        self.hp.save_sebek_changes(self.session)


