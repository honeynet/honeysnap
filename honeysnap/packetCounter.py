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

import base
import sys

class Counter(base.Base):
    """ Generic counting class 
        Args are:
        pcapObj: a pcap obj, a result of open_live() or open_offline()
    """
    def __init__(self, pcapObj):
        self.total = 0
        self.p = pcapObj

    def setFilter(self, filter):
        self.filter = filter
        self.p.setfilter(filter)

    def count(self):
        self.p.dispatch(-1, self.counter)

    def counter(self, hdr, data):
        self.total += 1

    def getCount(self):
        return self.total

    def resetCount(self):
        self.total = 0

    def writeResults(self):
        f = sys.stdout
        #f = open(self.outfile, "a")
        f.write("%-40s %10d\n" % (self.filter, self.total))
        #f.close()
