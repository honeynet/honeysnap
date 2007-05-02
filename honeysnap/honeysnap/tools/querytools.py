"""
querytools.py

Copyright (c) The Honeynet Project

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Some canned tools to make queries easier and to tie in with 
making nice graphs in hs-shell.

This code will be re-factored elsewhere in time

"""

# $Id$
        
from sqlalchemy import *
from sqlalchemy.ext.selectresults import SelectResults

from honeysnap.model.model import *             

_session = create_session()
                          

# other stuff to wrap at some point

# ssh packets per honeypot                                       
#  q = select( [honeypot_table.c.name, honeypot_table.c.id, func.sum(flow_table.c.packets)], 
#               flow_table.c.dport==22,  group_by=[honeypot_table.c.name, honeypot_table.c.id], distinct=True)


# e.g. count of ssh flows per honeypot                                                                                    
# q = select( [honeypot_table.c.name, honeypot_table.c.id, func.count(flow_table.c.id)], flow_table.c.dport==22, 
#               group_by=[honeypot_table.c.id, honeypot_table.c.name], distinct=True)


# top talkers to N honeypots            
#sub_q = select( [func.count(flow_table.c.honeypot_id).label('nodes'), ip_table.c.id, ip_table.c.ip_addr, ip_table.c.longitude, ip_table.c.latitude], flow_table.c.src_id==ip_table.c.id, distinct=True, use_labels=True, group_by=([flow_table.c.honeypot_id, ip_table.c.id, ip_table.c.ip_addr, ip_table.c.longitude, ip_table.c.latitude])).alias('sub_q')
#q = select( [sub_q.c.nodes, sub_q.c.ip_ip_addr, sub_q.c.ip_longitude, sub_q.c.ip_latitude], from_obj=[sub_q], order_by=[desc(sub_q.c.nodes)], group_by=[sub_q.c.nodes, sub_q.c.ip_ip_addr, sub_q.c.ip_longitude, sub_q.c.ip_latitude])
#q.append_having(sub_q.c.nodes>5)


def to_port_count(honeypot, starttime, endtime, port, timerange='DAY'):
    """
    Returns a list of counts of packets to port N from honeypot honeypot,
    grouped by timerange
    """
    pass
                                                                           
def from_port_count(honeypot, starttime, endtime, port, timerange='DAY'):
    """
    Return a list of counts of packets from port N on honeypot honeypot,
    grouped by timerange
    """
    pass
    
def src_ips_by_port(honeypot, starttime, endtime, port):
    """
    Return a list of src ip objects for a given dst port
    """  
    fq = _session.query(Flow)  
    ipq = _session.query(Ip)
    sr = SelectResults(fq)
    sr = sr.select(and_(flow_table.c.src_id==honeypot_table.c.ip_id, 
                        flow_table.c.dport==port,
                        flow_table.c.starttime > starttime,
                        flow_table.c.lastseen < endtime))
    return [ f.src for f in sr ]                       
    
def dst_ips_by_port(honeypot, starttime, endtime, port):
    """
    Returns a list of dst ip objects for a given dst port
    """                       
    fq = _session.query(Flow)  
    ipq = _session.query(Ip)
    sr = SelectResults(fq)
    sr = sr.filter(and_(flow_table.c.dst_id==honeypot_table.c.ip_id, 
                        flow_table.c.dport==port,
                        flow_table.c.starttime > starttime,
                        flow_table.c.lastseen < endtime))
    return [ f.dst for f in sr ]                        