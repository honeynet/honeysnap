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

class Base(object):
    """
    This should be a base class that provides commonly used functions.
    I decided to add this late in the game.  There are replicated functions
    in the below classes that should be put in here.
    """
    
    def __init__(self):
        self.p = None
        self.file = None
        self.filter = None
    
    def setOutput(self, file):
        self.outfile = file
        
    def setFilter(self, filter, file):
        self.filter = filter
        self.file = file
        self.p.setfilter(filter)

    def start(self):
        self.p.dispatch(-1, self.packetHandler)
        #self.printResults()
        
class Output(Base):
    """
    This class will provide a generic output interface so we can output
    in text, html, whatever.
    """
    def write():
        pass
