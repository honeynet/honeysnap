################################################################################
#   (c) 2007 The Honeynet Project
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
 
# $Id: model.py 5038 2007-01-27 17:22:46Z arthur $
import socket
from datetime import datetime
from sqlalchemy import * 
from sqlalchemy.ext.selectresults import SelectResults  
from sqlalchemy.ext.activemapper import metadata
 
class HoneysnapModelError(Exception):
    pass

class Enum(types.Unicode):
    """Enum type from http://www.sqlalchemy.org/trac/wiki/UsageRecipes/Enum"""
    def __init__(self, values, empty_to_none=False):      
        '''
        contruct an Enum type

        values : a list of values that are valid for this column
        empty_to_none : treat the empty string '' as None
        '''
        if values is None or len(values) is 0:
            raise exceptions.AssertionError('Enum requires a list of values')
        self.empty_to_none = empty_to_none
        self.values = values
        # the length of the string/unicode column should be the longest string
        # in values
        size = max([len(v) for v in values if v is not None])
        super(Enum, self).__init__(size)        


    def convert_bind_param(self, value, engine):
        if self.empty_to_none and value is '':
            value = None
        if value not in self.values:
            raise exceptions.AssertionError('"%s" not in Enum.values' % value)
        return super(Enum, self).convert_bind_param(value, engine)


    def convert_result_value(self, value, engine):
        if value not in self.values:
            raise exceptions.AssertionError('"%s" not in Enum.values' % value)
        return super(Enum, self).convert_result_value(value, engine) 

# Tables

honeypot_table = Table("honeypot", metadata,
    Column("id", Integer, primary_key=True), 
    Column("ip_id", Integer, ForeignKey("ip.id"), nullable=False, unique=True), 
    Column("name", Unicode, nullable=False),
    Column("state", Enum(['Up', 'Down', 'Unknown']), default="Up"),
    Column("description", Unicode, default=""),
    mysql_engine='INNODB',
)
  
# location data based on the fields from ip2location
ip_table = Table("ip", metadata,
    Column('id', Integer, primary_key=True),
    Column('ip_addr', String(16), nullable=False, index=True, unique=True),
    Column('latitude', Float, default=0.0),
    Column('longitude', Float, default=0.0),
    Column('isp', Unicode, default=None),    
    Column('domain', Unicode, default=None),
    Column('country', Unicode, default=None),
    Column('city', Unicode, default=None), 
    mysql_engine='INNODB',
)

flow_table = Table("flow", metadata,
    Column("id", Integer, primary_key=True),       
    Column("honeypot_id", Integer, ForeignKey("honeypot.id"), 
            nullable=False),
    Column("ip_proto", Integer, default=6, nullable=False), 
    Column("src_id", Integer, ForeignKey("ip.id"), nullable=False),
    Column("dst_id", Integer, ForeignKey("ip.id"), nullable=False),                        
    Column("sport", Integer, nullable=False),
    Column("dport", Integer, nullable=False),
    Column("packets", Integer, default=0),
    Column("bytes", Integer, default=0), 
    Column("starttime", DateTime, default=datetime.now()),
    Column("lastseen", DateTime, default=datetime.now()),   
    Column("filename", String, default='Not specified'),
    mysql_engine='INNODB', 
)      

sebek_table = Table("sebek", metadata,
    Column("id", Integer, primary_key=True),
    Column("honeypot_id", Integer, ForeignKey("honeypot.id"), 
        nullable=False),
    Column("version", Integer, nullable=False),
    Column("type", Integer, nullable=False),
    Column("time", DateTime, default=datetime.now()),
    Column("pid", Integer),
    Column("fd", Integer),
    Column("uid", Integer),
    Column("command", String),            
    # next two fields don't exist in sebek v2 data
    Column("parent_pid", Integer, default=0),
    Column("inode", Integer, default=0),
    Column("data", String),
    mysql_engine='INNODB',
)              


Index('flowindex', flow_table.c.starttime, 
                   flow_table.c.src_id, 
                   flow_table.c.sport, 
                   flow_table.c.dst_id,
                   flow_table.c.dport,
                   unique = True) 
                   
Index('sebekindex', sebek_table.c.honeypot_id,
                    sebek_table.c.type,
                    sebek_table.c.time,
                    sebek_table.c.pid,
                    sebek_table.c.fd,
                    sebek_table.c.uid,
                    sebek_table.c.command,
                    sebek_table.c.data,
                    unique = True)

# Objects
                        
class Honeypot(object):  
    """Honeypot stores details of individual honeypots"""
    def __init__(self, **kwargs):        
        for key in kwargs:       
            if key not in honeypot_table.c.keys():
                raise ValueError("Bad row name")            
            self.__dict__[key] = kwargs[key]
        
    def __repr__(self):
        return "[name: %s, ip_id: %s, state: %s, description: %s]\n" % \
                (self.name, self.ip_id, self.state, self.description)    

    @staticmethod
    def get_or_create(session, hp, name=None):
        """
        For one-off runs, create some Honeypot() db entries, checking if they exist first
        """
        if not name:
            name = "HS_Fake"  
        try:
            h = Honeypot.byIp(session, hp)            
        except HoneysnapModelError:
            ipid = Ip.id_byIp(hp)
            h = Honeypot(name=name, ip_id=ipid, state="Up")
            session.save(h)  
            session.flush()
        return h    
                
    @staticmethod
    def byIp(session, ip): 
        """Return a Honeypot object found by IP""" 
        try:    
            return session.query(Honeypot).selectone(Honeypot.c.ip_id == Ip.id_byIp(ip))
        except exceptions.InvalidRequestError:
            raise HoneysnapModelError("Honeypot not defined in DB!") 

    def save_flow_changes(self, session):
        """Save flow stats to db, dealing with dulicate entries"""
        try:    
            session.flush()
        except exceptions.SQLError, e:     
            if "IntegrityError" in e.args[0]:
                fq = session.query(Flow)          
                for flow in session.new:   
                    if type(flow) != type(Flow()):
                        continue
                    if fq.count(and_(Flow.c.src_id==flow.src_id, 
                                     Flow.c.sport==flow.sport, 
                                     Flow.c.dst_id==flow.dst_id, 
                                     Flow.c.dport==flow.dport, 
                                     Flow.c.starttime==flow.starttime))>0:
                        print "Duplicate flow - skipping: ", flow
                        session.delete(flow)
                session.flush()
                                
    def save_sebek_changes(self, session):
        """Save sebek records to db, dealing with dulicate entries"""
        try:    
            session.flush()
        except exceptions.SQLError, e:     
            if "IntegrityError" in e.args[0]:
                seen = {}
                sbk_q = session.query(Sebek)          
                for sbk in session.new:   
                    if type(sbk) != type(Sebek()):
                        continue        
                    if seen.get(sbk.unique_fields(), None): 
                        print 'Sebek record seen twice in import, ignoring'
                        session.delete(sbk)
                    else:          
                        seen[sbk.unique_fields()] = 1
                    if sbk_q.count(and_(Sebek.c.honeypot_id==sbk.c.honeypot_id,
                                        Sebek.c.type==sbk.c.type,
                                        Sebek.c.time==sbk.c.time,
                                        Sebek.c.pid==sbk.c.pid,
                                        Sebek.c.fd==sbk.c.fd,
                                        Sebek.c.uid==sbk.c.uid,
                                        Sebek.c.command==sbk.c.command,
                                        Sebek.c.data==sbk.c.data))>0:
                        print "Duplicate sebek record - skipping: ", sbk
                        session.delete(sbk)
                session.flush()                            

class Ip(object):
    """IP address and location details""" 
    ipid_cache = {}    
      
    def __init__(self, **kwargs):                 
        for key in kwargs:           
            if key not in ip_table.c.keys():
                raise ValueError("Bad row name")            
            self.__dict__[key] = kwargs[key]
    
    def __repr__(self):
        return "[ip_addr: %s, latitude: %s, longitude: %s, isp: %s, domain: %s, country: %s, city: %s]" % \
               (self.ip_addr, self.latitude, self.longitude, self.isp, 
               self.domain, self.country, self.city)
               
    @staticmethod
    def id_byIp(ip_addr):  
        """return id field for a IP object"""                        
        #if Ip.ipid_cache.has_key(ip_addr): 
        #    return Ip.ipid_cache[ip_addr] 
        ip = ip_table.select(ip_table.c.ip_addr==ip_addr).execute().fetchone() 
        if ip:                   
            #Ip.ipid_cache[ip_addr] = ip.id
            return ip.id  
        r = ip_table.insert().execute(ip_addr=ip_addr)        
        id = r.last_inserted_ids()[0] 
        #Ip.ipid_cache[ip_addr] = id  
        return id
                           
class Flow(object):
    """Flow stats"""
    def __init__(self, **kwargs):
        for key in kwargs:                      
            if key == 'icmp_type':
                self.icmp_type = kwargs[key]
                continue
            if key == 'icmp_code':
                self.icmp_code = kwargs[key]
                continue            
            if key not in flow_table.c.keys(): 
                raise ValueError("Bad row name %s" % key)
            if (key == 'starttime' or key == 'lastseen') and (type(kwargs[key]) != type(datetime.now())):
                self.__dict__[key] = datetime.utcfromtimestamp(kwargs[key])
                continue
            self.__dict__[key] = kwargs[key]
        
    def __repr__(self):  
        if self.ip_proto == socket.IPPROTO_ICMP: 
            return "[honeypot: %s, ip_proto: %s, src: %s, dst: %s, type: %s, code: %s, packets: %s, bytes: %s, starttime: %s, lastseen: %s, filename: %s]" % \
                (self.honeypot_id, self.ip_proto, self.src_id, self.dst_id, self.icmp_type, self.icmp_code, 
                self.packets, self.bytes, self.starttime, self.lastseen, self.filename)             
        else:
            return "[honeypot: %s, ip_proto: %s, src: %s, sport: %s, dst: %s, dport: %s, packets: %s, bytes: %s, starttime: %s, lastseen: %s, filename: %s]" % \
                (self.honeypot_id, self.ip_proto, self.src_id, self.sport, self.dst_id, self.dport, 
                self.packets, self.bytes, self.starttime, self.lastseen, self.filename)

    def _get_icmp_type(self):
        return self.sport
        
    def _set_icmp_type(self, type):
        self.sport = type
        
    def _get_icmp_code(self):
        return self.dport
        
    def _set_icmp_code(self, code):
        self.dport = code 
        
    icmp_type = property(_get_icmp_type, _set_icmp_type, doc="icmp type")    
    icmp_code = property(_get_icmp_code, _set_icmp_code, doc="icmp code")

    @staticmethod
    def sum(session, sum_col, and_conditions=[], or_conditions=[]):
        """
        return a sum over sum_col with given conditions
        and_conditions and or_conditions should be a list of conditions, all of which will be applied
        either or both of these can be empty
        """
        fsr = SelectResults(session.query(Flow)) 
        for and_cond in and_conditions:
            fsr = fsr.filter(and_(and_cond))
        for or_cond in or_conditions:
            fsr = fsr.filter(or_(and_cond))
        r = fsr.sum(sum_col)
        if not r:
            return 0
        else:
            return r
       
class Sebek(object):
    """Sebek data""" 
    def __init__(self, **kwargs):
        for key in kwargs:   
            if key not in sebek_table.c.keys():
                raise ValueError("Bad row name")  
            if key == 'time' and type(kwargs[key]) != type(datetime.now()):
                kwargs[key] = datetime.utcfromtimestamp(kwargs[key])   
            self.__dict__[key] = kwargs[key]

    def __repr__(self):
        return "[honeypot: %s, version: %s, type: %s, time: %s, pid: %s, fd: %s, uid: %s, parent_pid: %s, inode: %s, command: %s, data: %s]" % \
                (self.honeypot.id, self.version, self.type, self.time, self.pid, self.fd, self.uid, 
                self.parent_pid, self.inode, self.command, self.data)   
                

    def __str__(self):
        if self.version == 3:
             return "[%s ip:%s parent:%s pid:%s uid:%s fd:%s inode:%s com:%s] %s" % (self.time, 
                    self.honeypot.ip_id, self.parent_pid, self.pid, self.uid, self.fd, self.inode, self.command, self.data)
        else:
             return "[%s ip:%s pid:%s uid:%s fd:%s com:%s] %s" % (self.time, 
                    self.honeypot.ip_id, self.pid, self.uid, self.fd, self.command, self.data)  

    def unique_fields(self):
        return (self.honeypot_id, self.type, self.time, self.pid, self.fd, self.uid, self.command, self.data)

    @staticmethod
    def num_of_type(session, type, hp, starttime=datetime.utcfromtimestamp(0), endtime=datetime.now()):
        """Return count() of sebek records within date range with type type"""
        return session.query(Sebek).count(and_(Sebek.c.honeypot_id==hp.id, Sebek.c.type==type, Sebek.c.time>starttime, Sebek.c.time<endtime)) 
        
    @staticmethod
    def get_lines(session, hp, type, starttime, endtime, excludes=None):
        if excludes:
            return session.query(Sebek).select(and_(Sebek.c.time>starttime, Sebek.c.time<endtime, Sebek.c.honeypot_id==hp.id, Sebek.c.type==type, not_(Sebek.c.command.in_(*excludes))))
        else:
            return session.query(Sebek).select(and_(Sebek.c.time>starttime, Sebek.c.time<endtime, Sebek.c.honeypot_id==hp.id, Sebek.c.type==type))
            

# Table -> Object mappers

mapper(Honeypot, honeypot_table, properties={ 
    "flows": relation(Flow, lazy=None, passive_deletes=True, backref="honeypot", 
        cascade="all, delete-orphan"),
    "sebek_lines": relation(Sebek, lazy=None, passive_deletes=True, backref="honeypot", 
        cascade="all, delete-orphan"),
})                                                    
      
mapper(Ip, ip_table)
mapper(Flow, flow_table)
mapper(Sebek, sebek_table) 

# init and create tables if needed  
def connect_to_db(dburi, debug=False):
    db = create_engine(dburi)
    db.echo = debug
    metadata.connect(db)
    metadata.create_all()
    return db

