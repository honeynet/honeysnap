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

from util import renameFile

class smtpDecode(object):
    def __init__(self):
        self.statemgr = None
        self.count = 0
        
    def decode(self, state, statemgr):
        self.statemgr = statemgr
        f = state.flow
        if f.dport == 25:
            state.close()
            state.open("rb")
            d = state.fp.readlines()
            dlow = [l.lower() for l in d]
            to = [l for l in dlow if l.find("rcpt to") >= 0]
            subj = [l for l in dlow if l.find("subject") >=0]
            if len(to) == 0:
                return
            if len(subj) == 0:
                subj.append("")
            realname = "mail-message-%d" % self.count
            self.count +=1 
            renameFile(state, realname)
            # assume the first entry in each list is the correct one
            print "file: %s" % realname
            print "\t" + to[0]
            print "\t" + subj[0]
