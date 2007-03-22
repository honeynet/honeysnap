#!/usr/bin/python
  
# $Id$

from honeysnap.model.model import *
from sqlalchemy import *
import socket   
import optparse
import time

from sqlalchemy.ext.selectresults import SelectResults

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
ipQuery = session.query(Ip)
flowQuery = session.query(Flow) 
hpotCount = hpQuery.count()

def printPortStats(hp, startdate, enddate, port):
    totalCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= startdate, 
                           Flow.c.starttime < enddate],
                           [Flow.c.sport == port,
                            Flow.c.dport == port]) 
    
    inCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= startdate, 
                           Flow.c.starttime < enddate,
                           Flow.c.dst_id == hp.ip_id], 
                           [Flow.c.sport == port,
                            Flow.c.dport == port])

    outCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= startdate, 
                           Flow.c.starttime < enddate,
                           Flow.c.src_id == hp.ip_id],
                           [Flow.c.sport == port,
                            Flow.c.dport == port])

    print "\tTotal Count port:", port, "=", totalCount
    print "\tInbount Count port:", port, "=", inCount
    print "\tOutbound Count port:", port, "=", outCount

print "Trying to figure out the earliest date in the db"
flowSR = SelectResults(flowQuery).order_by(Flow.c.starttime)

for x in flowSR[:1]:
    earliestDate = x.starttime

startDate = earliestDate

workingDate = startDate
currentDate = time.time()

while(workingDate < currentDate):
    nextDate = workingDate + 86400   # num seconds/day
    print "Daily stats for", workingDate

    for hp in hpQuery.select():
        print "Honeypot:", ipQuery.get_by(id=hp.ip_id).ip_addr

        totalByteCount = Flow.sum(session, Flow.c.bytes, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate, 
                           Flow.c.starttime < nextDate])

        inboundByteCount = Flow.sum(session, Flow.c.bytes, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.dst_id == hp.ip_id])

        outboundByteCount = Flow.sum(session, Flow.c.bytes, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.src_id == hp.ip_id])

        print "\tTotal Bytes:", totalByteCount
        print "\tInboud Bytes:", inboundByteCount
        print "\tOutbound Bytes:", outboundByteCount

        totalPktCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate, 
                           Flow.c.starttime < nextDate])

        inboundPktCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.dst_id == hp.ip_id])

        outboundPktCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.src_id == hp.ip_id])

        print "\tTotal packets:", totalPktCount
        print "\tInboud packets:", inboundPktCount
        print "\tOutbound packets:", outboundPktCount

        totalTcpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                      Flow.c.starttime >= workingDate, 
                      Flow.c.starttime < nextDate,
                      Flow.c.ip_proto == socket.IPPROTO_TCP])

        inboundTcpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.dst_id == hp.ip_id,
                           Flow.c.ip_proto == socket.IPPROTO_TCP])


        outboundTcpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.src_id == hp.ip_id,
                           Flow.c.ip_proto == socket.IPPROTO_TCP])

        print "\tTotal Tcp pkts:", totalTcpCount
        print "\tInboud Tcp pkts:", inboundTcpCount
        print "\tOutbound Tcp pkts:", outboundTcpCount

        totalUdpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                      Flow.c.starttime >= workingDate, 
                      Flow.c.starttime < nextDate,
                      Flow.c.ip_proto == socket.IPPROTO_UDP])

        inboundUdpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.dst_id == hp.ip_id,
                           Flow.c.ip_proto == socket.IPPROTO_UDP])


        outboundUdpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.src_id == hp.ip_id,
                           Flow.c.ip_proto == socket.IPPROTO_UDP])

        print "\tTotal Udp pkts:", totalUdpCount
        print "\tInboud Udp pkts:", inboundUdpCount
        print "\tOutbound Udp pkts:", outboundUdpCount

        totalIcmpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                      Flow.c.starttime >= workingDate, 
                      Flow.c.starttime < nextDate,
                      Flow.c.ip_proto == socket.IPPROTO_ICMP])

        inboundIcmpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.dst_id == hp.ip_id,
                           Flow.c.ip_proto == socket.IPPROTO_ICMP])

        outboundIcmpCount = Flow.sum(session, Flow.c.packets, [Flow.c.honeypot_id == hp.id, 
                           Flow.c.starttime >= workingDate,
                           Flow.c.starttime < nextDate,
                           Flow.c.src_id == hp.ip_id,
                           Flow.c.ip_proto == socket.IPPROTO_ICMP])

        print "\tTotal Icmp pkts:", totalIcmpCount
        print "\tInboud Icmp pkts:", inboundIcmpCount
        print "\tOutbound Icmp pkts:", outboundIcmpCount

        totalOtherCount = totalPktCount - totalTcpCount - totalUdpCount - totalIcmpCount
        inboundOtherCount = inboundPktCount - inboundTcpCount - inboundUdpCount - inboundIcmpCount
        outboundOtherCount = outboundPktCount - outboundTcpCount - outboundUdpCount - outboundIcmpCount

        print "\tTotal Other pkts:", totalOtherCount
        print "\tInbound Other pkts:", inboundOtherCount
        print "\tOutbound Other pkts:", outboundOtherCount

        for port in [21, 22, 23, 25, 53, 80, 443, 6667, 1101]: 
            printPortStats(hp, time.asctime(workingDate), nextDate, port)

    workingDate = nextDate
