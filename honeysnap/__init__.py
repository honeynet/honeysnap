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
import pcapy, sys
import socket
from pcapy import *
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import re
import string
import gzip
import os
#import dataextractor
from threading import Thread
from ConfigParser import SafeConfigParser
import tcpflow

FILTERS = {'do_packets':'src host %s', 
			'do_ftp':'src host %s and dst port 21',
			'do_ssh':'src host %s and dst port 22',
			'do_telnet':'src host %s and dst port 23',
			'do_smtp':'src host %s and dst port 25',
			'do_http':'src host %s and dst port 80',
			'do_https':'src host %s and dst port 443',
			'do_sebek':'src host %s and udp port 1101',
			'do_irc':'src host %s and dst port 6667'}
		
def ipnum(ip) :
	"Return a numeric address for an ip string"
	v = 0L
	for x in ip.split(".") :
		v = (v << 8) | int(x);
	return v

class Base:
	"""
	This should be a base class that provides commonly used functions.
	I decided to add this late in the game.  There are replicated functions
	in the below classes that should be put in here.
	"""
	def setOutput(self, file):
		self.outfile = file
		
class Counter(Base):
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
		f = open(self.outfile, "a")
		f.write("%-40s %10d\n" % (self.filter, self.total))
		f.close()

class Summarize(Base):
	"""
	Summarize takes a pcapObj, and an optional dbObj that is a mysql db connection.
	This class reads the pcap data, hands it to a decoder, and then keys each packet
	by (srcip, dstip, dport).  The count of each tuple is kept. 
	Utimately you get a packet count for each outgoing connection.
	This class works best if you use setFilter to filter by "src $HONEYPOT"
	"""
	def __init__(self, pcapObj, dbObj):
		self.tcpports = {}
		self.udpports = {}
		self.icmp = {}
		self.p = pcapObj
		if dbObj:
			self.db = summaryTable(dbObj)
		else:
			self.db =None
		# Query the type of the link and instantiate a decoder accordingly.
		datalink = self.p.datalink()
		if pcapy.DLT_EN10MB == datalink:
			self.decoder = EthDecoder()
		elif pcapy.DLT_LINUX_SLL == datalink:
			self.decoder = LinuxSLLDecoder()
		else:
			raise Exception("Datalink type not supported: " % datalink)

	def setFilter(self, filter, file):
		self.filter = filter
		self.file = file
		self.p.setfilter(filter)

	def start(self):
		self.p.dispatch(-1, self.packetHandler)
		#self.printResults()

	def packetHandler(self, hdr, data):
		#print self.decoder.decode(data)
		try:
			pkt = self.decoder.decode(data)
		except:
			return
		try:
			proto = pkt.child().child().protocol
			shost = pkt.child().get_ip_src()
			dhost = pkt.child().get_ip_dst()
		except: 
			return

		try:
			if proto == socket.IPPROTO_TCP:
				dport = pkt.child().child().get_th_dport()
				sport = pkt.child().child().get_th_sport()
				key = (shost, dhost, dport)
				if key not in self.tcpports:
					self.tcpports[key] = 0
				self.tcpports[key] += 1
				if self.db:
					self.db.queueInsert((proto, ipnum(shost), sport, ipnum(dhost), dport, self.filter, self.file, hdr.getts()[0], self.tcpports[key])) 
			if proto == socket.IPPROTO_UDP:
				dport = pkt.child().child().get_uh_dport()
				sport = pkt.child().child().get_uh_sport()
				key = (shost, dhost, dport)
				if key not in self.udpports:
					self.udpports[key] = 0
				self.udpports[key] += 1
				if self.db:
					self.db.queueInsert((proto, ipnum(shost), sport, ipnum(dhost), dport, self.filter, self.file, hdr.getts()[0], self.udpports[key])) 
		except:
			return

	def printResults(self):
		print "TCP TRAFFIC SUMMARY:"
		print "%-15s %-15s %8s %10s" % ("SOURCE", "DEST", "DPORT", "COUNT")
		for key, val in self.tcpports.items():
			if val > 10:
				print "%-15s %-15s %8s %10s" % (key[0], key[1], key[2], val)
		if len(self.udpports) > 0:
			print "UDP TRAFFIC SUMMARY:"
			print "%-15s %-15s %8s %10s" % ("SOURCE", "DEST", "DPORT", "COUNT")
			for key, val in self.udpports.items():
				if val > 10:
					print "%-15s %-15s %8s %10s" % (key[0], key[1], key[2], val)
	
	def writeResults(self):
		f = open(self.outfile, 'a')
		f.write("TCP TRAFFIC SUMMARY:\n")
		f.write("%-15s %-15s %8s %10s\n" % ("SOURCE", "DEST", "DPORT", "COUNT"))
		for key, val in self.tcpports.items():
			#if val > 10:
			f.write("%-15s %-15s %8s %10s\n" % (key[0], key[1], key[2], val))
		if len(self.udpports) > 0:
			f.write("UDP TRAFFIC SUMMARY:\n")
			f.write("%-15s %-15s %8s %10s\n" % ("SOURCE", "DEST", "DPORT", "COUNT"))
			for key, val in self.udpports.items():
				#if val > 10:
				f.write("%-15s %-15s %8s %10s\n" % (key[0], key[1], key[2], val))
		f.close()
		if self.db:
			self.db.doInserts()
				

class PcapRE(Base):
	"""
	Takes a pcapObj as an argument.
	
	"""
	def __init__(self, pcapObj):
		self.exp = None
		self.p = pcapObj
		self.results = {}
		self.doWordSearch = 0
		# Query the type of the link and instantiate a decoder accordingly.
		datalink = self.p.datalink()
		if pcapy.DLT_EN10MB == datalink:
			self.decoder = EthDecoder()
		elif pcapy.DLT_LINUX_SLL == datalink:
			self.decoder = LinuxSLLDecoder()
		else:
			raise Exception("Datalink type not supported: " % datalink)

	def setRE(self, pattern):
		"""
		Arg is a string that will be treated as a regular expression
		"""
		self.exp = re.compile(pattern)
		self.pattern = pattern

	def setFilter(self, filter):
		self.p.setfilter(filter)

	def setWordSearch(self, searcher):
		""" Takes an instance of class wordSearch as arg"""
		self.doWordSearch = 1
		self.searcher = searcher
		
	def start(self):
		self.p.dispatch(-1, self.packetHandler)
		#self.printResults()

	def packetHandler(self, hdr, data):
		pay = None
		m = None
		try:
			pkt = self.decoder.decode(data)
		except:
			return
		try:
			proto = pkt.child().child().protocol
		except:
			return
		try:
			if proto == socket.IPPROTO_TCP:
				ip = pkt.child()
				shost = ip.get_ip_src()
				dhost = ip.get_ip_dst()
				tcp = pkt.child().child()
				pay = tcp.child().get_buffer_as_string()
				dport = tcp.get_th_dport()
				key = (proto, shost, dhost, dport)
			if proto == socket.IPPROTO_UDP:
				ip = pkt.child()
				shost = ip.get_ip_src()
				dhost = ip.get_ip_dst()
				udp = pkt.child().child()
				pay = udp.child().get_buffer_as_string()
				dport = udp.get_uh_dport()
				key = (proto, shost, dhost, dport)
		except:
			return
		if pay is not None and self.exp is not None:
			m = self.exp.search(pay)
			if m:
				if key not in self.results:
					self.results[key] = 0
				self.results[key] += 1
				if self.doWordSearch:
					self.searcher.findWords(pkt, pay)
	
	def printResults(self):
		for key, val in self.results.items():
			print "Pattern: %-10s %-5s %-15s %-15s %-5s %10s" % (self.pattern, key[0], key[1], key[2], key[3], val)
		if self.doWordSearch:
			#self.searcher.printResults()
			self.searcher.writeResults()

	def writeResults(self):
		f = open(self.outfile, 'a')
		f.write("%-10s %-5s %-15s %-15s %-5s %10s\n" % ("PATTERN", "PROTO", "SOURCE", "DEST", "DPORT", "COUNT"))
		for key, val in self.results.items():
			f.write("%-10s %-5s %-15s %-15s %-5s %10s\n" % (self.pattern, key[0], key[1], key[2], key[3], val))
		if self.doWordSearch:
			self.searcher.writeResults()
		f.close()

class wordSearch(Base):
	"""
	wordSeach is an auxillary of pcapRE. It allows you to pass a list of words 
	you wish to search for to pcapRE.
	"""
	def __init__(self):
		self.results = {}
		self.words = []

	def _buildkey(self, pkt):
		try:
			proto = pkt.child().child().protocol
			if proto == socket.IPPROTO_TCP:
				ip = pkt.child()
				shost = ip.get_ip_src()
				dhost = ip.get_ip_dst()
				tcp = pkt.child().child()
				dport = tcp.get_th_dport()
				key = (proto, shost, dhost, dport)
			if proto == socket.IPPROTO_UDP:
				ip = pkt.child()
				shost = ip.get_ip_src()
				udp = pkt.child().child()
				dport = udp.get_uh_dport()
				key = (proto, shost, dhost, dport)
		except:
			return
		return key
		
	def findWords(self, pkt, data):
		for w in self.words:
			if string.find(data, w) >= 0:
				key = self._buildkey(pkt)
				if key is not None:
					if key not in self.results[w]:
						self.results[w][key] = 0 
					self.results[w][key] += 1
				
	def setWords(self, wordstr):
		self.words = []
		for w in wordstr.split(" "):
			self.results[w] = {}
			self.words.append(w)

	def printResults(self):
		for word, cons in self.results.items():
			for k in cons:
				print "%s: %s\t\t%s\t\t%s\t\t%s\t\t\t%s" % (word, k[0], k[1], k[2], k[3], self.results[word][k])

	def writeResults(self):
		f = open(self.outfile, 'a')
		f.write("Word Matches\n")
		f.write("%-10s %-5s %-17s %-17s %-7s %10s\n" % ("WORD", "PROTO", "SOURCE", "DEST", "DPORT", "COUNT"))
		for word, cons in self.results.items():
			for k in cons:
				f.write("%-10s %-5s %-17s %-17s %-7s %10s\n" % (word, k[0], k[1], k[2], k[3], self.results[word][k]))
		f.close()
	
		

#class gzToPipe(Thread):
class gzToPipe:
	"""
	My original intention was to use a threaded fifo so multiple modules could access
	the unzipped data at the same time.
	fifo's are giving me trouble, so for now this will just use plain old files
	XXX if we stick with plain tmp files, we need to use tmpfile module to make it secure
	and cross platform
	"""
	def __init__(self, zipfile, pipefile):
		#Thread.__init__(self)
		self.pipefile = pipefile
		self.zipfile = gzip.open(zipfile, 'rb')
		#self.fifo = os.mkfifo(pipe)
		#self.pipe = open(pipe, "w+")
		self.pipe = open(self.pipefile, "wb")

	def run(self) :
		while 1:
			chunk = self.zipfile.read(1024)
			if not chunk:
				break
			self.pipe.write(chunk)
		self.zipfile.close()
		self.pipe.close()

	def getFile(self):
		return self.pipefile

	def destroy(self):
		os.unlink(self.pipefile)
		

def processFile(honeypots, file, options, dbargs=None):
		"""
		Process a pcap file.
		honeypots is a list of honeypot ip addresses
		file is the pcap file to parse
		This function will run any enabled options for each pcap file
		"""
		fifo = options["tmp_file_directory"] + "/pipefile"
		gz = gzToPipe(file, fifo)
		gz.run()
		try:
			outfile = open(options["output_data_directory"] + "/results", 'a+')
		except IOError:
			# we have some error opening the file
			# first we check if the output dir exists
			if not os.path.exists(options["output_data_directory"]):
				# the directory isn't there
				try:
					os.mkdir(options["output_data_directory"])
					# now we can create the output file
					outfile = open(options["output_data_directory"] + "/results", 'a+')
				except:
					print "Error creating output directory"
					sys.exit(1)
			else:
				# there is something at that path. Is it a directory?
				if not os.path.isdir(options["output_data_directory"]):
					print "Error: output_data_directory exists, but is not a directory."
				else:
					print "Unknown Error creating output file"
				sys.exit(1)

			
			
		print "Processing file: %s" % file
		outfile.write("\n\nResults for file: %s\n" % file)
		outfile.write("Outgoing Packet Counts\n")
		outfile.write("%-40s %10s\n" % ("Filter", "Packets"))
		outfile.flush()
		for ipaddr in honeypots:
			for name, val in options.items():
				if name in FILTERS and val == "YES":
					filt = FILTERS[name]
					p = open_offline(fifo)
					#p = open_offline("/tmp/fifo")
					c = Counter(p)
					c.setOutput(options["output_data_directory"] + "/results")
					f = filt % ipaddr
					c.setFilter(f)
					c.count()
					count = c.getCount()
					c.writeResults()

		if options["summarize_incoming"] == "YES":
			#print "INCOMING CONNECTIONS"
			outfile.write("INCOMING CONNECTIONS\n")
			outfile.flush()
			p = open_offline(fifo)
			if dbargs:
				db = dbConnection(dbargs)
			else:
				db = None
			s = Summarize(p, db)
			filt = 'dst host ' + string.join(honeypots, ' or dst host ')
			s.setFilter(filt, file)
			s.setOutput(options["output_data_directory"] + "/results")
			s.start()
			s.writeResults()


		if options["summarize_outgoing"] == "YES":
			#print "\nOUTGOING CONNECTIONS"
			outfile.write("\nOUTGOING CONNECTIONS\n")
			outfile.flush()
			p = open_offline(fifo)
			s = Summarize(p, db)
			filt = 'src host ' + string.join(honeypots, ' or src host ')
			s.setFilter(filt, file)
			s.setOutput(options["output_data_directory"] + "/results")
			s.start()
			s.writeResults()


		if options["do_irc_summary"] == "YES":
			"""
			Here we will use PcapRE to find packets on port 6667 with "PRIVMSG"
			in the payload.  Matching packets will be handed to wordsearch 
			to hunt for any matching words.
			"""
			#print "\nIRC SUMMARY"
			outfile.write("\nIRC SUMMARY\n")
			outfile.flush()
			p = open_offline(fifo)
			# XXX TODO: words should be moved into the config file
			# should we have the config file point to a seperate word file
			# or just store them in the config file?
			words = '0day access account admin auth bank bash #!/bin binaries binary bot card cash cc cent connect crack credit dns dollar ebay e-bay egg flood ftp hackexploit http leech login money /msg nologin owns ownz password paypal phish pirate pound probe prv putty remote resolved root rooted scam scan shell smtp sploit sterling sucess sysop sys-op trade uid uname uptime userid virus warez' 
			ws = wordSearch()
			ws.setWords(words)
			ws.setOutput(options["output_data_directory"] + "/results")
			r = PcapRE(p)
			r.setFilter("port 6667")
			r.setRE('PRIVMSG')
			r.setWordSearch(ws)
			r.setOutput(options["output_data_directory"] + "/results")
			r.start()
			r.writeResults()

		if options["do_irc_detail"] == "YES":
			#outfile.write("\nIRC DETAIL\n")
			print "Extracting from IRC"
			outfile.flush()
			p = open_offline(fifo)
			de = tcpflow.tcpFlow(p)
			de.setFilter("port 6667")
			de.setOutput(options["output_data_directory"] +"/results")
			de.setOutdir(options["output_data_directory"]+ "/irc-extract")
			de.start()
			del de
		
		if options["do_http"] == "YES" and options["do_files"] == "YES":
			print "Extracting from http"
			p = open_offline(fifo)
			de = tcpflow.tcpFlow(p)
			de.setFilter("port 80")
			de.setOutdir(options["output_data_directory"]+ "/http-extract")
			de.setOutput(options["output_data_directory"] + "/results")
			de.start()

		if options["do_ftp"] == "YES" and options["do_files"] == "YES":
			print "Extracting from ftp"
			p = open_offline(fifo)
			de = tcpflow.tcpFlow(p)
			de.setFilter("port 20")
			de.setOutdir(options["output_data_directory"] + "/ftp-extract")
			de.setOutput(options["output_data_directory"] + "/results")
			de.start()

		if options["do_smtp"] == "YES" and options["do_files"] == "YES":
			print "Extracting from smtp"
			p = open_offline(fifo)
			de = tcpflow.tcpFlow(p)
			de.setFilter("port 25")
			de.setOutdir(options["output_data_directory"] + "/smtp-extract")
			de.setOutput(options["output_data_directory"] + "/results")
			de.start()

		if options["do_rrd"] == "YES":
			print "RRD not currently supported"
		
		if options["do_sebek"] == "YES":
			print "Sebek not currently supported"


def usage():
	use = """Usage:
honeysnap.py <config file>

Please see the accompanying documentation for instructions on configuration.
	"""
	print use
	
def cleanup(options):
	"""
	Clean up empty files, etc.
	"""
	datadir = options["output_data_directory"]
	for dir in ["/irc-extract", "/http-extract", "/ftp-extract", "/smtp-extract"]:
		if os.path.isdir(datadir+dir):
			files = os.listdir(datadir+dir)
		else:
			continue
		for f in files:
			file = datadir + dir + "/" + f
			if os.stat(file).st_size == 0:
				os.unlink(file)

def main():
	if len(sys.argv) > 1:
		#ipaddr = sys.argv[1]
		#file = sys.argv[2]
		config = sys.argv[1]
		parser = SafeConfigParser()
		parser.read(config)
		try:
			inputdir = parser.get("IO", "INPUT_DATA_DIRECTORY")
			outputdir = parser.get("IO", "OUTPUT_DATA_DIRECTORY")
			tmpdir = parser.get("IO", "TMP_FILE_DIRECTORY")
			honeypots = parser.get("IO", "HONEYPOTS")
		except:
			print "Missing a required IO parameter in config file."
			sys.exit(1)
		try:
			datemask = parser.get("IO", "DATEMASK")
		except:
			datemask = 0
		honeypots = honeypots.split()
		dbargs = None
		if parser.has_section("DATABASE"):
			from dbconnect import *
			dbargs = {}
			dbargs["host"] = parser.get("DATABASE", "host")
			dbargs["user"] = parser.get("DATABASE", "user")
			dbargs["password"] = parser.get("DATABASE", "password")
			dbargs["db"] = parser.get("DATABASE", "db")

		if datemask != 0:
			dateregex = re.compile(datemask)
		else:
			dateregex = re.compile("*")

		options = {"do_packets":"NO",
					"do_telnet":"NO",
					"do_ssh":"NO",
					"do_http":"NO",
					"do_https":"NO",
					"do_ftp":"NO",
					"do_smtp":"NO",
					"do_irc":"NO",
					"do_irc_summary":"NO",
					"do_irc_detail":"NO",
					"do_sebek":"NO",
					"do_rrd":"NO",
					"do_files": "NO"
					}
		
		for i in parser.items("OPTIONS"):
			options[i[0]] = i[1]

		options["output_data_directory"] = outputdir
		options["tmp_file_directory"] = tmpdir

		nomatch = 0

		files = os.listdir(inputdir)
		for f in files:
			if dateregex.match(f) and string.find(f, "pcap.log.gz") > 0:
				processFile(honeypots, inputdir+"/" + f, options, dbargs)
				nomatch = 1

		if nomatch != 1:
			print "No pcap files found!"
	
		cleanup(options)

	else:
		usage()

if __name__ == "__main__":
	#import profile
	#profile.run('main()', 'mainprof')
	main()
