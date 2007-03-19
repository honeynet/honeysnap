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
from time import asctime, gmtime, time
from sqlalchemy import * 
from sqlalchemy.ext.selectresults import SelectResults  
from sqlalchemy.ext.activemapper import metadata

# max length of sebek data
# must be < ~700 for mysql but can be larger for postgres
MAX_SBK_DATA_SIZE = 512
                         
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
  
# we store timestamps directly here because MySQL doesn't store sub-second precision
# http://bugs.mysql.com/bug.php?id=8523

honeypot_table = Table("honeypot", metadata,
    Column("id", Integer, primary_key=True), 
    Column("ip_id", Integer, ForeignKey("ip.id"), nullable=False, unique=True), 
    Column("name", Unicode(64), nullable=False),
    Column("state", Enum(['Up', 'Down', 'Unknown']), default="Up"),
    Column("description", Unicode(512), default="", nullable="False"),
    mysql_engine='INNODB',
)
  
# location data based on the fields from ip2location
ip_table = Table("ip", metadata,
    Column('id', Integer, primary_key=True),
    Column('ip_addr', String(16), nullable=False, index=True, unique=True),
    Column('latitude', Float, default=0.0, nullable=False),
    Column('longitude', Float, default=0.0, nullable=False),
    Column('isp', Unicode(256), default=None),    
    Column('domain', Unicode(256), default=None),
    Column('country', Unicode(256), default=None),
    Column('city', Unicode(256), default=None), 
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
    Column("packets", Integer, default=0, nullable=False),
    Column("bytes", Integer, default=0, nullable=False), 
    Column("starttime", Float(50), nullable=False),
    Column("lastseen", Float(50), nullable=False),   
    Column("filename", String(1024), default='Not specified', nullable=False),
    mysql_engine='INNODB', 
)      
          
sebek_table = Table("sebek", metadata,
    Column("id", Integer, primary_key=True),
    Column("honeypot_id", Integer, ForeignKey("honeypot.id"), 
        nullable=False),
    Column("version", Integer, nullable=False),
    Column("type", Integer, nullable=False),
    Column("timestamp", Float(50), nullable=False),
    Column("pid", Integer, nullable=False),
    Column("fd", Integer, nullable=False),
    Column("uid", Integer, nullable=False),
    Column("command", String(64), nullable=False),            
    # next two fields don't exist in sebek v2 data
    Column("parent_pid", Integer, default=0, nullable=False),
    Column("inode", Integer, default=0, nullable=False),
    Column("data", String(MAX_SBK_DATA_SIZE)),
    mysql_engine='INNODB',  
)              
  
# IRC related tables

irc_talker_table = Table('irc_talker', metadata,
    Column('id', Integer, primary_key=True),
    Column('name', Unicode(512), nullable=False, unique=True),
)
                                   
irc_message_table = Table('irc_message', metadata,
    Column('id', Integer, primary_key=True),    
    Column('honeypot_id', Integer, ForeignKey('honeypot.id'),
        nullable=False),
    Column('from_id', Integer, ForeignKey('irc_talker.id'), nullable=False),
    Column('to_id', Integer, ForeignKey('irc_talker.id'), default=None),
    Column('command', String(64), nullable=False),
    Column('src_id', Integer, ForeignKey('ip.id'), nullable=False),   
    Column('dst_id', Integer, ForeignKey('ip.id'), nullable=False),    
    Column('sport', Integer, nullable=False),
    Column('dport', Integer, nullable=False),
    Column('timestamp', Float(50), nullable=False),
    Column('text', String(512))
)

# Indexes

Index('flowindex', flow_table.c.starttime, 
                   flow_table.c.src_id, 
                   flow_table.c.sport, 
                   flow_table.c.dst_id,
                   flow_table.c.dport,
                   unique = True) 
                   
Index('sebekindex', sebek_table.c.honeypot_id, 
                    sebek_table.c.type,
                    sebek_table.c.timestamp,
                    sebek_table.c.pid,
                    sebek_table.c.fd,
                    sebek_table.c.uid,
                    sebek_table.c.command,
                    sebek_table.c.data,
                    unique = True)   
                    
Index('ircindex', irc_message_table.c.honeypot_id,
                  irc_message_table.c.from_id,
                  irc_message_table.c.to_id,
                  irc_message_table.c.command,
                  irc_message_table.c.src_id,
                  irc_message_table.c.dst_id,
                  irc_message_table.c.timestamp,
                  irc_message_table.c.text,
                  unique=True)                    

# Objects
                        
class Honeypot(object):  
    """Honeypot stores details of individual honeypots"""
    def __init__(self, **kwargs):        
        for key in kwargs:       
            if key not in honeypot_table.c.keys():
                raise ValueError("Bad row name %s" % key)            
            self.__dict__[key] = kwargs[key]
        
    def __repr__(self):
        return "[name: %s, ip_id: %s, state: %s, description: %s]" % \
                (self.name, self.ip_id, self.state, self.description)    

    @staticmethod
    def get_or_create(session, hp, name=None):
        """
        For one-off runs, create some Honeypot() db entries, checking if they exist first
        """
        if not name:
            name = "HS_Fake"  
        try:
            h = Honeypot.by_ip(session, hp)            
        except HoneysnapModelError:
            ipid = Ip.id_by_ip(hp)
            h = Honeypot(name=name, ip_id=ipid, state="Up")
            session.save(h)  
            session.flush()
        return h    
                
    @staticmethod
    def by_ip(session, ip): 
        """Return a Honeypot object found by IP""" 
        try:    
            return session.query(Honeypot).selectone(Honeypot.c.ip_id == Ip.id_by_ip(ip))
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
                        print 'Sebek record seen twice in import, ignoring', repr(sbk)
                        session.delete(sbk) 
                        continue
                    else:   
                        seen[sbk.unique_fields()] = 1
                    if sbk_q.count(and_(Sebek.c.honeypot_id==sbk.c.honeypot_id,
                                        Sebek.c.type==sbk.c.type,
                                        Sebek.c.timestamp==sbk.c.timestamp,
                                        Sebek.c.pid==sbk.c.pid,
                                        Sebek.c.fd==sbk.c.fd,
                                        Sebek.c.uid==sbk.c.uid,
                                        Sebek.c.command==sbk.c.command,
                                        Sebek.c.data==sbk.c.data))>0:
                        print "Duplicate sebek record - skipping"
                        session.delete(sbk) 
                session.flush()                            
     
    def save_irc_changes(self, session):
        """Save irc changes to db, dealing with duplicate entries"""
        try:
            session.flush()
        except exceptions.SQLError, e:
            if "IntegrityError" in e.args[0]:
                seen = {}
                irc_q = session.query(IRC_Message)
                for msg in session.new:
                    if type(msg) != type(IRC_Message()):
                        continue 
                    if seen.get(msg.unique_fields(), None):
                        print 'IRC message seen twice in import, ignoring'
                    else:
                        seen[msg.unique_fields()] = 1
                    if irc_q.count(and_(
                            irc_message_table.c.honeypot_id==msg.c.honeypot_id,
                            irc_message_table.c.from_id==msg.c.from_id,
                            irc_message_table.c.to_id==msg.c.to_id,
                            irc_message_table.c.command==msg.c.command,
                            irc_message_table.c.src_id==msg.c.src_id,
                            irc_message_table.c.dst_id==msg.c.dst_id,
                            irc_message_table.c.timestamp==msg.c.timestamp,
                            irc_message_table.c.text==msg.c.text)) > 0:
                        print "Duplicate IRC message - skipping: ", msg
                        session.delete(msg)
                session.flush()

class Ip(object):
    """IP address and location details""" 
    ipid_cache = {}    
      
    def __init__(self, **kwargs):                 
        for key in kwargs:           
            if key not in ip_table.c.keys():
                raise ValueError("Bad row name %s" % key)            
            self.__dict__[key] = kwargs[key]
    
    def __repr__(self):
        return "[ip_addr: %s, latitude: %s, longitude: %s, isp: %s, domain: %s, country: %s, city: %s]" % \
               (self.ip_addr, self.latitude, self.longitude, self.isp, 
               self.domain, self.country, self.city)
               
    @staticmethod
    def id_by_ip(ip_addr):  
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
            self.__dict__[key] = kwargs[key]
        
    def __repr__(self):  
        return "[honeypot: %s, ip_proto: %s, src: %s, dst: %s, type: %s, code: %s, packets: %s, bytes: %s, starttime: %s, lastseen: %s, filename: %s]" % \
            (self.honeypot_id, self.ip_proto, self.src_id, self.dst_id, self.icmp_type, self.icmp_code, 
            self.packets, self.bytes, self.starttime, self.lastseen, self.filename)             

    def __str__(self):
        if self.ip_proto == socket.IPPROTO_ICMP: 
            return "[honeypot: %s, ip_proto: %s, src: %s, dst: %s, type: %s, code: %s, packets: %s, bytes: %s, starttime: %s, lastseen: %s, filename: %s]" % \
                (self.honeypot_id, self.ip_proto, self.src_id, self.dst_id, self.icmp_type, self.icmp_code, 
                self.packets, self.bytes, asctime(gmtime(self.starttime)), asctime(gmtime(self.lastseen)), self.filename)             
        else:
            return "[honeypot: %s, ip_proto: %s, src: %s, sport: %s, dst: %s, dport: %s, packets: %s, bytes: %s, starttime: %s, lastseen: %s, filename: %s]" % \
                (self.honeypot_id, self.ip_proto, self.src_id, self.sport, self.dst_id, self.dport, 
                self.packets, self.bytes, asctime(gmtime(self.starttime)), asctime(gmtime(self.lastseen)), self.filename)        

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


class SebekMapperExtension(MapperExtension):
    """Enforce size limits on fields"""
    def before_insert(self, mapper, connection, instance):
        """called before an object instance is INSERTed into its table."""
        if len(instance.data) > MAX_SBK_DATA_SIZE:
            instance.data = instance.data[0:MAX_SBK_DATA_SIZE]
        return EXT_PASS
    def before_update(self, mapper, connection, instance):
        """called before an object instance is UPDATED"""
        if len(instance.data) > MAX_SBK_DATA_SIZE:
            instance.data = instance.data[0:MAX_SBK_DATA_SIZE]
        return EXT_PASS
       
class Sebek(object):
    """Sebek data""" 
    def __init__(self, **kwargs):
        for key in kwargs:   
            if key not in sebek_table.c.keys():
                raise ValueError("Bad row name %s" % key)  
            self.__dict__[key] = kwargs[key] 
        if self.data and len(self.data) > MAX_SBK_DATA_SIZE:
            self.data = self.data[0:MAX_SBK_DATA_SIZE]            

    def __repr__(self):
        return "[honeypot: %s, version: %s, type: %s, timestamp: %s, pid: %s, fd: %s, uid: %s, parent_pid: %s, inode: %s, command: %s, data: %s]" % \
                (self.honeypot.id, self.version, self.type, self.timestamp, self.pid, self.fd, self.uid, 
                self.parent_pid, self.inode, self.command, self.data)   
    def __str__(self):   
        if self.version == 3:
             return "[%s ip:%s parent:%s pid:%s uid:%s fd:%s inode:%s com:%s] %s" % (asctime(gmtime(self.timestamp)), 
                    self.honeypot.ip_id, self.parent_pid, self.pid, self.uid, self.fd, self.inode, self.command, self.data)
        else:
             return "[%s ip:%s pid:%s uid:%s fd:%s com:%s] %s" % (asctime(gmtime(self.timestamp)), 
                    self.honeypot.ip_id, self.pid, self.uid, self.fd, self.command, self.data)  

    def unique_fields(self):
        return (self.honeypot_id, self.type, self.timestamp, self.pid, self.fd, self.uid, self.command, self.data)

    @staticmethod
    def num_of_type(session, hp, type, starttime=0, endtime=time()):
        """Return count() of sebek records within date range with type type"""
        return session.query(Sebek).count(and_(Sebek.c.honeypot_id==hp.c.id, Sebek.c.type==type, \
            Sebek.c.timestamp>starttime, Sebek.c.timestamp<endtime)) 
        
    @staticmethod
    def get_lines(session, hp, type, starttime, endtime, excludes=None):
        if excludes:
            return session.query(Sebek).select(and_(Sebek.c.timestamp>starttime, Sebek.c.timestamp<endtime, \
                Sebek.c.honeypot_id==hp.c.id, Sebek.c.type==type, not_(Sebek.c.command.in_(*excludes))))
        else:
            return session.query(Sebek).select(and_(Sebek.c.timestamp>starttime, Sebek.c.timestamp<endtime, \
                Sebek.c.honeypot_id==hp.c.id, Sebek.c.type==type))
            
class IRC_Talker(object):
    """Store details of a sender or receiver of an IRC messsage (could be channel, nick or server)"""
    def __init__(self, **kwargs):        
        for key in kwargs:       
            if key not in irc_talker_table.c.keys():
                raise ValueError("Bad row name %s" % key)            
            self.__dict__[key] = kwargs[key]

    def __repr__(self):
        return "[id: %s, name: %s]" % (self.id, self.name)

    def __str__(self):
        return "[name: %s]" % (self.name)
          
class IRC_Message(object):
    """store irc message details"""
    def __init__(self, **kwargs):
        for key in kwargs:   
            if (key not in irc_message_table.c.keys()):
                if key not in ['irc_src', 'irc_dst']:
                    raise ValueError("Bad row name %s" % key)  
            self.__dict__[key] = kwargs[key]    

    def __repr__(self):
        return "[timestamp: %s, id: %s, src_id: %s, dst_id: %s,  src_port: %s, dst_port: %s, command: %s, from_id: %s, to_id: %s, text: %s]" % \
            (asctime(gmtime(self.timestamp)), self.id, self.src_id, self.dst_id, 
            self.sport, self.dport, self.command, self.from_id, self.to_id, self.text) 

    def _get_channel(self):
        """return channel if dst is a channel"""
        if self.to.name[0] == '#':
            return self.dst.name
        else:
            return None
            
    channel = property(_get_channel, None)        
            
    def unique_fields(self):
        """return unique fields"""
        return (self.honeypot_id, self.from_id, self.to_id, self.command, self.src_id, self.dst_id, self.timestamp, self.text)

# Table -> Object mappers

mapper(Honeypot, honeypot_table, properties={ 
    "flows": relation(Flow, lazy=None, passive_deletes=True, backref="honeypot", 
        cascade="all, delete-orphan"),
    "sebek_lines": relation(Sebek, lazy=None, passive_deletes=True, backref="honeypot", 
        cascade="all, delete-orphan"), 
    "irc_messages": relation(IRC_Message, lazy=None, passive_deletes=True, backref="honeypot",
        cascade="all, delete-orphan"),
})                                                    
      
mapper(Ip, ip_table)
mapper(Flow, flow_table)
mapper(Sebek, sebek_table, extension=SebekMapperExtension())                 
mapper(IRC_Talker, irc_talker_table, properties={
    "sent": relation(IRC_Message, lazy=None, passive_deletes=True, cascade="all, delete-orphan", 
        primaryjoin=irc_message_table.c.from_id==irc_talker_table.c.id, backref="irc_src"),
    "received": relation(IRC_Message, lazy=None, passive_deletes=True, cascade="all, delete-orphan", 
        primaryjoin=irc_message_table.c.to_id==irc_talker_table.c.id, backref="irc_dst"),
})

mapper(IRC_Message, irc_message_table)

# init and create tables if needed  
def connect_to_db(dburi, debug=False):
    db = create_engine(dburi)
    db.echo = debug
    metadata.connect(db)
    metadata.create_all()
    return db

