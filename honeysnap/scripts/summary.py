#!/usr/bin/python
  
# $Id$

from honeysnap.model.model import *
from sqlalchemy import *
import socket   
import optparse


op = optparse.OptionParser()
op.add_option('--dburi', dest='dburi', help='dburi to connect to') 
op.add_option('--debug', dest='debug', action="store_const", const=True, help='Show generated SQL?')
opts, args = op.parse_args()
if not opts.dburi:
    op.error('Must give a dburi with --dburi=')
    sys.exit(1)  
              
if opts.debug:
	debug=True
else:
	debug=False

engine = connect_to_db(opts.dburi, debug)
session = create_session()

hpQuery = session.query(Honeypot)
flowQuery = session.query(Flow) 
ipQuery = session.query(Ip)
hpotCount = hpQuery.count()

print "\nWe have %d honeypots " % hpotCount
for hp in hpQuery.select():
    print "Printing preliminary stats for each honeypot" 
    print "-----------------------------------------------"
    print hp.name, ": ", ipQuery.get_by(id=hp.ip_id).ip_addr
    hpotId = hp.id

    flowCount = flowQuery.count_by(Flow.c.honeypot_id == hpotId)
    flowInCount = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId, Flow.c.dst_id == hp.ip_id))
    flowOutCount = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId, Flow.c.src_id == hp.ip_id))

    print "\twith a total of %d flows in the database." % flowCount
    print "\t\t%d inbound" % flowInCount 
    print "\t\t%d outbound" % flowOutCount

    #flowIpDistinctCount = select([Flow.c.source_ip], 
    #                             Flow.c.honeypot_id == hpotId, distinct=True)
    #print flowIpDistinctCount.execute().rowcount


    tcpRes = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                     Flow.c.ip_proto == socket.IPPROTO_TCP))
    print "\tWe have %d tcp flows" % tcpRes

    tcpIn = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                    Flow.c.dst_id == hp.ip_id, 
                                    Flow.c.ip_proto == socket.IPPROTO_TCP))
    print "\t\t%d inbound" % tcpIn
    tcpOut = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                     Flow.c.src_id == hp.ip_id,
                                     Flow.c.ip_proto == socket.IPPROTO_TCP))
    print "\t\t%d outbound" % tcpOut
    
    udpRes = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                     Flow.c.ip_proto == socket.IPPROTO_UDP))
    print "\tWe have %d udp flows" % udpRes

    udpIn = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                    Flow.c.dst_id == hp.ip_id,
                                    Flow.c.ip_proto == socket.IPPROTO_UDP))
    print "\t\t%d inbound" % udpIn
    udpOut = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                     Flow.c.src_id == hp.ip_id,
                                     Flow.c.ip_proto == socket.IPPROTO_UDP))
    print "\t\t%d outbound" % udpOut
    
    
    icmpRes = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                      Flow.c.ip_proto == socket.IPPROTO_ICMP))

    print "\tWe have %d icmp flows" % icmpRes
    icmpIn = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                     Flow.c.dst_id == hp.ip_id,
                                     Flow.c.ip_proto == socket.IPPROTO_ICMP))

    print "\t\t%d inbound" % icmpIn
    icmpOut = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                      Flow.c.src_id == hp.ip_id,
                                      Flow.c.ip_proto == socket.IPPROTO_ICMP))
    print "\t\t%d outbound" % icmpOut
    
    otherRes = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                       Flow.c.ip_proto != socket.IPPROTO_ICMP, 
                                       Flow.c.ip_proto != socket.IPPROTO_TCP, 
                                       Flow.c.ip_proto != socket.IPPROTO_UDP))
    print "\tWe have %d other flows" % otherRes
    
    otherIn = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                      Flow.c.dst_id == hp.ip_id,
                                      Flow.c.ip_proto != socket.IPPROTO_ICMP, 
                                      Flow.c.ip_proto != socket.IPPROTO_TCP,
                                      Flow.c.ip_proto != socket.IPPROTO_UDP))
    print "\t\t%d inbound" % otherIn

    otherOut = flowQuery.count_by(and_(Flow.c.honeypot_id == hpotId,
                                       Flow.c.src_id == hp.ip_id,
                                       Flow.c.ip_proto != socket.IPPROTO_ICMP, 
                                       Flow.c.ip_proto != socket.IPPROTO_TCP,
                                       Flow.c.ip_proto != socket.IPPROTO_UDP))
    print "\t\t%d outbound" % otherOut
