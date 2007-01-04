################################################################################
# (c) 2007, The Honeynet Project
#   Author: Arthur Clune arthur@honeynet.org.uk
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
                     
from base import Base          
from singletonmixin import HoneysnapSingleton 

class flowDecode(Base):
    """Base class to handle output for things like http/ftp/smtp decoding"""
    def __init__(self):
        super(flowDecode, self).__init__()  
        hs = HoneysnapSingleton.getInstance() 
        self.options = hs.getOptions()   
        self.requested_files = {}
        self.served_files = {}
        for hp in self.options['honeypots']: 
            self.served_files[hp] = [] 
            self.requested_files[hp] = []
                                              
    def print_summary(self, message):                        
        """Generic function to print time ordered set of messages"""
        for hp in self.options['honeypots']:                 
            self.doOutput(message % hp)
            if self.requested_files[hp] or self.served_files[hp]:  
                for item in ['requested_files', 'served_files']:  
                    if item == 'served_files' and self.options['print_served'] != 'YES':
                        self.doOutput('\n%s requests served by honeypot\n' % len(self.served_files[hp]))
                        break                    
                    a = self.__dict__[item][hp]
                    if a:    
                        self.doOutput("\n%s:\n\n" % item)
                        a.sort()
                        for (ts, outstring) in a:  
                            self.doOutput(outstring)
                    else:
                        self.doOutput("\n%s: No files seen\n\n" % item) 
            else:
                self.doOutput('\tNo traffic seen\n\n')    
 
    def add_flow(self, ts, src, dst, message):
        """work out if a file is served by or requested from a HP"""
        if src in self.options['honeypots']:
            hp = src
            direction = 'served_files'
        else:
            hp = dst      
            direction = 'requested_files'
        self.__dict__[direction][hp].append( [ts, message])