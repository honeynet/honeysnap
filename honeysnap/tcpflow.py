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

import os, sys
import impacket
import socket
import pcapy
from pcapy import *
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import traceback

NUM_RESERVED_FDS=25
HASH_SIZE=1009
FLOW_FINISHED=(1 << 0)
FLOW_FILE_EXISTS=(1 << 1)

def ipnum(ip) :
	"Return a numeric address for an ip string"
	v = 0L
	for x in ip.split(".") :
		v = (v << 8) | int(x);
	return v

class flow:
	def __init__(self):
		self.src = None
		self.dst = None
		self.sport = None
		self.dport = None

class flow_state:
	def __init__(self):
		self.next = None # link to next flow state
		self.flow = None # Description of the flow
		self.isn = None  # Initial Seq Number
		self.fp = None   # file pointer for this flows data
		self.pos = 0
		self.flags = 0
		self.last_access = 0 # time of last access

	def __cmp__(self, other):
		# to facilitate sorting a list of states by last_access
		return cmp(self.last_access, other.last_access)


class flow_state_manager:
	def __init__(self):
		self.current_time = 0
		self.max_fds = self.get_max_fds() - NUM_RESERVED_FDS
		self.fd_ring = []
		self.flow_hash = {}
		self.curent_time = 0
		self.outdir = None

	def get_max_fds(self):
		"""
		this needs to be a xplatform method of getting max # of file descriptors
		"""
		return os.sysconf('SC_OPEN_MAX')

	def setOutdir(self, outdir):
		self.outdir = outdir

	def hash_flow(self, flow):
		hash =  (((flow.sport & 0xff) | ((flow.dport & 0xff) << 8) | ((ipnum(flow.src) & 0xff) << 16) | ((ipnum(flow.dst) & 0xff) << 24) ) % HASH_SIZE)
		return hash

	def create_state(self, flow, isn):
		#import pdb
		#pdb.set_trace()
		new_state = flow_state()
		#index = self.hash_flow(flow)
		index = flow
		if index in self.flow_hash:
			new_state.next = self.flow_hash[index]
		self.flow_hash[index] = new_state

		new_state.flow = flow
		new_state.isn = isn
		new_state.last_access = self.current_time+1
		self.current_time +=1

		return new_state
	
	def find_flow_state(self, flow):
		#index = self.hash_flow(flow)
		index = flow
		if index in self.flow_hash:
			state = self.flow_hash[index]
		else:
			return None
		if state.flow == flow:
			state.last_access = self.current_time+1
			self.current_time +=1
			return state
		else:
			while state.next is not None:
				#print "looking at state.next"
				if state.next == state:
					#print "state.next = state, thats bad"
					return None
				state = state.next
				if state.flow == flow:
					state.last_access = self.current_time+1
					self.current_time +=1
					return state
				
		return None

	def attempt_fopen(self, state, filename):
		try:
			fp = open(filename, "a")
		except IOError:
			#print "IOError, opening file %s" % filename
			return None
		return fp

	def flow_filename(self, flow):
		"""
		filename should be:
		"%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d"
		"""
		name = "%s/%s.%s-%s.%s" % (self.outdir, flow.src, flow.sport, flow.dst, flow.dport)
		return name

	def open_file(self, state):
		filename = self.flow_filename(state.flow)

		if state.fp is not None:
			if not state.fp.closed:
				# the state fp is already open, return it
				return state.fp

		state.fp = self.attempt_fopen(state, filename)
		self.fd_ring.append(state)

		if len(self.fd_ring) == self.max_fds:
			# maxed out the fds
			# close the oldest
			self.contract_fd_ring()

		return state.fp

	def close_file(self, state):
		if state.fp is None:
			#print "in close_file, state.fp is None!!"
			return 0

		state.fp.flush()
		state.fp.close()
		state.fp = None
		state.pos = 0
		return 1
	
	def contract_fd_ring(self):

		deletes = []
		for state in self.fd_ring:
			# check to see if this state was one of the last 20 accessed
			if state.last_access <= self.current_time - 20:
				# this state is not one of the 20 most recently accessed
				# slate it for delete
				deletes.append(state)

		for i in deletes:
			self.close_file(i)
			self.fd_ring.remove(i)

				
		# this method is too slow
		"""
		for state in self.fd_ring:
			# check to see if this state was one of the last 20 accessed
			if state.last_access <= self.current_time - 50:
				self.close_file(state)
				self.fd_ring.remove(state)
				return
				deletes.append(state)

		# close 30 oldest files 
		self.fd_ring.sort()
		for i in range(0,30):
			self.close_file(self.fd_ring[0])
			del self.fd_ring[0]
		"""

class tcpFlow:
	def __init__(self, pcapObj):
		self.p = pcapObj
		self.states = flow_state_manager()
		self.outdir = ""
		# Query the type of the link and instantiate a decoder accordingly.
		datalink = self.p.datalink()
		if pcapy.DLT_EN10MB == datalink:
			self.decoder = EthDecoder()
		elif pcapy.DLT_LINUX_SLL == datalink:
			self.decoder = LinuxSLLDecoder()
		else:
			raise Exception("Datalink type not supported: " % datalink)
		
	
	def packetHandler(self, hdr, data):
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

		if proto == socket.IPPROTO_TCP:
			self.process_tcp(pkt, shost, dhost)

	def process_ip(self, hdr, data):
		pass

	def process_tcp(self, pkt, src, dst):
		tcp = pkt.child().child()
		this_flow = flow()
		this_flow.src = src
		this_flow.dst = dst
		this_flow.sport = tcp.get_th_sport()
		this_flow.dport = tcp.get_th_dport()
		seq = tcp.get_th_seq()
		data = tcp.child().get_buffer_as_string()

		self.store_packet(this_flow, data, seq)


	def store_packet(self, flow, data, seq):
		bytes_per_flow = 1000000
		length = len(data)
		state = self.states.find_flow_state(flow)
		if state is None:
			#print "state not found, creating new"
			state = self.states.create_state(flow, seq)

		if state.flags&FLOW_FINISHED:
			#print "flow finished"
			return

		offset = seq - state.isn
		if offset < 0:
			# seq < isn, drop it
			return

		if bytes_per_flow and (offset > bytes_per_flow):
			# too many bytes for this flow, drop it
			print "too many bytes for flow, dropping packet"
			return

		#import pdb
		#pdb.set_trace()
		if state.fp is None:
			fp = self.states.open_file(state)
			if fp is None:
				#print "open_file returned none!!"
				sys.exit(1)

		if bytes_per_flow and (offset + length > bytes_per_flow):
			# long enough, mark this flow finished
			#print "flow marked finished due to length"
			state.flags |= FLOW_FINISHED
			length = bytes_per_flow - offset

		if offset != state.pos:
			#print "offeset != state.pos"
			fpos = offset
			#state.fp.seek(fpos)

		state.fp.write(data)
		state.fp.flush()

		state.pos = offset+length

		if state.flags&FLOW_FINISHED:
			#print "flow marked finished, closing file"
			self.states.close_file(state)

	def start(self):
		while 1:
			try:
				hdr, data = self.p.next()
				self.packetHandler(hdr, data)
			except PcapError:
				return
			except:
				traceback.print_exc(file=sys.stdout)

		"""
		try:
			self.p.dispatch(-1, self.packetHandler)
		except:
			print "Exception in user code:"
			print '-'*60
			traceback.print_exc(file=sys.stdout)
			print '-'*60
		"""
		print "finished"

	def setFilter(self, filter):
		self.p.setfilter(filter)

	def setOutdir(self, dir):
		self.outdir = dir
		self.states.setOutdir(dir)
		if not os.path.exists(self.outdir):
			os.mkdir(self.outdir)

	def setOutput(self, file):
		self.outfile = file

	def writeResults(self):
		"""TODO: I would like to implement some sort of summarization
		of the data files that were written during the run...
		"""
		pass

if __name__ == "__main__":
	from honeysnap import gzToPipe
	import sys
	f = sys.argv[1]
	gz = gzToPipe(f, "/tmp/fifo")
	gz.run()
	pcapObj = open_offline("/tmp/fifo")
	tflow = tcpFlow(pcapObj)
	tflow.setFilter("not port 445")
	tflow.start()

