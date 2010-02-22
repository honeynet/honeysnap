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

import sys
                 
class Output(object):
    """
    This class will provide a generic output interface so we can output
    in text, html, whatever.
    """
    def write():
        pass

class outputSTDOUT(Output):
    
    def __init__(self):
        self._file = sys.stdout

    def write(self,msg):
        self._file.write(msg)
        
    def __call__(self, msg):
        if isinstance(msg, str):
            self._file.write(msg)
        elif callable(msg):
            self._file.write(msg())
        else:
            self._file.write(str(msg))                    

class rawFileOutput(Output):

    def __init__(self, fileHandle, mode='w'):
        self._file = filehandle
        self._filename = self._file.name
        self._mode = mode

    def __call__(self, msg):
        if isinstance(msg, str):
            self._file.write(msg)
        elif callable(msg):
            self._file.write(msg())
        else:
            self._file.write(str(msg))

    def close(self):
        self._file.close()

    def _getClosed(self):
        return self._file.closed

    closed = property(_getClosed)

    def _setmode(self, mode):
        self._mode = mode

    def _getmode(self):
        return self._mode
    mode = property(_getmode, _setmode)

    def open(self):
        if self.closed:
            self._file = open(self._filename, self.mode)


class rawPathOutput(rawFileOutput):

    def __init__(self, path, mode='w'):
        self._filename = path
        self._file = open(self._filename, mode)
        self.mode = mode   


class Message(object):
    """
    Base class for messages that would be passed between modules.
    """ 

class stringMessage(Message):

    def __init__(self, msg=None):
        self._msg = msg

    def __call__(self):
        return self._msg

    def __repr__(self):
        print self._msg

    def __str__(self):
        return self._msg

    def _getM(self):
        return self._msg

    def _setM(self, m):
        self._msg = m
    msg = property(_getM, _setM)


class stringFormatMessage(stringMessage):

    def __init__(self, msg=None, format=None):
        stringMessage.__init__(self)
        self._fmt = format

    def __call__(self):
        return self._fmt % self._msg

    def __repr__(self):
        print self._fmt % self._msg

    def __str__(self):
        return self._fmt % self._msg

    def _setF(self, fmt):
        self._fmt = fmt

    def _getF(self):
        return self._fmt
    format = property(_getF, _setF)   
    
    
        