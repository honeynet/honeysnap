################################################################################
# (c) 2005, The Honeynet Project
#	Author: Jed Haile  jed.haile@thelogangroup.biz
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

import MySQLdb
import sys
import _mysql_exceptions

class dbConnection:
	def __init__(self, opts):
		self.db = MySQLdb.connect(**opts)

	def destroy(self) :
		self.db.close()
		self.db = None

class summaryTable:
	fields = "proto, srcip, sport, dstip, dport, filter, file, date, count"
	def __init__(self, dbConnObj):
		#(self.proto, self.srcip, self.sport, self.dstip, self.dport, self.filter, self.file, self.date) = args
		self.conn = dbConnObj
		self.inserts = []
		
	def queueInsert(self, args):
		# args is a tuple containing all the fields
		self.inserts.append(args)

	def doInserts(self):
		if len(self.inserts) > 0:
			c = self.conn.db.cursor()
			query = """insert into summary (proto, srcip, sport, dstip, dport, filter, file, date, count) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
			try:
				c.executemany(query, self.inserts)
			except _mysql_exceptions.Warning:
				print "\nMySQL warning: %s - %s\n" % (sys.exc_type, sys.exc_value)

class reTable:
	fields = "content, re, proto, srcip, dstip, dport, filter, file, date"
	def __init__(self, dbConnObj):
		#(self.content, self.re, self.proto, self.srcip, self.dstip, self.dport, self.filter, self.file, self.date) = args
		self.conn = dbConnObj
		self.inserts = []
		
	def queueInsert(self, args):
		# args is a tuple containing all the fields
		self.inserts.append(args)

	def doInserts(self, con):
		c = self.conn.cursor()
		query = """insert into wordSearch (content, re, proto, srcip, dstip, dport, filter, file, date) values (%s, %s, %s, %s, %s, %s, %s, %s)"""
		c.executemany(query, self.inserts)

class wordSearchTable:
	fields = "content, word, proto, srcip, dstip, dport, filter, file, date"
	def __init__(self, dbConnObj):
		#(self.content, self.word, self.proto, self.srcip, self.dstip, self.dport, self.filter, self.file, self.date) = args
		self.conn = dbConnObj
		self.inserts = []
		
	def queueInsert(self, args):
		# args is a tuple containing all the fields
		self.inserts.append(args)

	def doInserts(self, con):
		self.c = conn.cursor()
		query = """insert into wordSearch (content, word, proto, srcip, dstip, dport, filter, file, date, count) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
		c.executemany(query, self.inserts)
	


