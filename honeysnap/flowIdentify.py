################################################################################
# (c) 20056, The Honeynet Project
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
import magic
from util import mdsum

class flowIdentify:
    """
    A class to determine the type of a file.
    """
    def __init__(self):
        self.id = magic.file

    def identify(self, state):
        """
        state: an instance of tcpflow.flow_state
        data: captured data to be identified
        """
        state.filetype = self.id(state.fname)
        print "filetype: %s" % state.filetype
        mdsum(state.fname)
        


