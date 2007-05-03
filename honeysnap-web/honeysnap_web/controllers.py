from turbogears import controllers, expose
from model import *
from turbogears import identity, redirect
from turbogears import validators, validate, error_handler, paginate
from turbogears.database import session
from turbogears.widgets import PaginateDataGrid, TableForm, TextField 
from turbogears.widgets.big_widgets import CalendarDateTimePicker
from cherrypy import request, response    
import time    
# from honeysnap_web import json
import logging
log = logging.getLogger("honeysnap_web.controllers")
        
class Flows(controllers.Controller):
    """Flow data""" 
    
    # require = identity.in_group("admin")
    
    FlowGrid = PaginateDataGrid(
        fields = [
            PaginateDataGrid.Column('starttime', 'starttime', 'Starttime',
                options=dict(sortable=True)),  
            PaginateDataGrid.Column('lastseen', 'lastseen', 'Endtime',
                options=dict(sortable=True)),                  
            PaginateDataGrid.Column('honeypot_id', 'honeypot_name', 'Honeypot',
                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('src_id', 'ip_src_addr', 'Source',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('dst_id', 'ip_dst_addr', 'Destination',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('sport', 'sport', 'Src Port',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('dport', 'dport', 'Dst Port',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('packets', 'packets', 'Packets'),
            PaginateDataGrid.Column('bytes', 'bytes', 'Bytes'),
            ]
    )   

    FlowSearchForm = TableForm( 
        fields=[ 
                TextField(name="honeypot", label="honeypot"),
                TextField(name="bytes_less", label="Less than N Bytes"),
                TextField(name="bytes_more", label="More than N Bytes"),
                TextField(name="packets_less", label="Less than N Packets"),
                TextField(name="packets_less", label="More than N Packets"),
                TextField(name="duration_min", label="Lasts more than N seconds"),
                TextField(name="duration_max", label="Lasts less than N seconds"),
                CalendarDateTimePicker(name="starttime",
                                label="Start time",
                                validator=validators.DateTimeConverter(),
                                default=datetime(1990,1,1,0,0)),
                CalendarDateTimePicker(name="endtime",
                                label="End time",
                                default=datetime.now(),
                                validator=validators.DateTimeConverter())
                        ],
               submit_text="Search",
           )
    
    @expose(template="honeysnap_web.templates.details") 
    @paginate('messages', default_order='starttime', limit=25)
    def details(self):
       """display flows in a paged table"""    
       fq = session.query(Flow)
       flows = SelectResults(fq)
       return { 'request': None, 'form' : self.FlowSearchForm, 'messages' : flows,
                'list': self.FlowGrid }    

class SebekMessages(controllers.Controller):
    """Sebek output"""

    # require = identity.in_group("admin")
    
    SebekMessageGrid = PaginateDataGrid(
        fields = [
            PaginateDataGrid.Column('timestamp', 'timestamp', 'Time',
                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('honeypot_id', 'honeypot_name', 'Honeypot',
                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('type', 'type', 'Type',
                options=dict(sortable=True)),                                                                               
            PaginateDataGrid.Column('pid', 'pid', 'PID',
                options=dict(sortable=True)),   
            PaginateDataGrid.Column('uid', 'uid', 'UID',
                options=dict(sortable=True)),
            PaginateDataGrid.Column('fd', 'fd', 'FD',
                options=dict(sortable=True)),                  
            PaginateDataGrid.Column('parent_pid', 'parent_pid', 'PPID',
                options=dict(sortable=True)),    
            PaginateDataGrid.Column('inode', 'inode', 'INODE',
                options=dict(sortable=True)),                
            PaginateDataGrid.Column('command', 'command', 'Command',
                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('data', 'data', 'Data',
                options=dict(sortable=True)),
            ]                               
    )   
    
    SebekSearchForm = TableForm( 
        fields=[ 
                TextField(name="data", label="Data"),
                TextField(name="honeypot", label="Honeypot"),
                TextField(name="type",   label="Type"),
                TextField(name="pid",  label="PID"),
                TextField(name="uid", label="UID"),
                TextField(name="fd", label="FD"),
                TextField(name="command", label="Command"),
                TextField(name="parent_pid", label="PPID"),
                TextField(name="inode", label="INODE"),
                CalendarDateTimePicker(name="starttime",
                                label="Start time",
                                validator=validators.DateTimeConverter(),
                                default=datetime(1990,1,1,0,0)),
                CalendarDateTimePicker(name="endtime",
                                label="End time",
                                default=datetime.now(),
                                validator=validators.DateTimeConverter())
                        ],
               submit_text="Search",
           )                          
    
    @expose(template="honeysnap_web.templates.details") 
    @paginate('messages', default_order='timestamp', limit=25)
    def details(self):
       """display sebek messages in a paged table""" 
       sbq = session.query(Sebek)
       messages = SelectResults(sbq)
       return { 'request': None, 'form' : self.SebekSearchForm, 'messages' : messages,
                'list': self.SebekMessageGrid }    
               
class IRCMessages(controllers.Controller):
    """IRC output"""

    #require = identity.in_group("admin")

    IRCMessageGrid = PaginateDataGrid(
        fields=[                                                     
            PaginateDataGrid.Column('timestamp', 'timestamp', 'Time',
                            options=dict(sortable=True)),                    
            PaginateDataGrid.Column('honeypot_id', 'honeypot_name', 'Honeypot',
                                options=dict(sortable=True)),                                                                            
            PaginateDataGrid.Column('src_id', 'ip_src_addr', 'Source',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('dst_id', 'ip_dst_addr', 'Destination',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('port', 'port', 'Port',
                                options=dict(sortable=True)),                                                                                                           
            PaginateDataGrid.Column('from_id', 'irc_from_name', 'From',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('to_id', 'irc_to_name', 'To',
                                options=dict(sortable=True)),                    
            PaginateDataGrid.Column('command', 'command', 'Command',
                                options=dict(sortable=True)),
            PaginateDataGrid.Column('text', 'text', 'Text')                                
            ],
        )

    IRCSearchForm = TableForm( 
        fields=[ 
            TextField(name="text", label="Text"),
            TextField(name="irc_from", label="From"),
            TextField(name="irc_to",   label="To"),
            TextField(name="command",  label="Command"),
            TextField(name="src", label="IP Source", 
                      validator=validators.Regex(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')),
            TextField(name="dst", label="IP Destination", 
                      validator=validators.Regex(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')),  
            TextField(name="port", label="Port"),
            TextField(name="honeypot", label="Honeypot"),
            CalendarDateTimePicker(name="starttime",
                            label="Start time",
                            validator=validators.DateTimeConverter(),
                            default=datetime(1990,1,1,0,0)),
            CalendarDateTimePicker(name="endtime",
                            label="End time",
                            default=datetime.now(),
                            validator=validators.DateTimeConverter())
        ],
        submit_text="Search"
    )  
       
    @expose(template="honeysnap_web.templates.details") 
    @paginate('messages', default_order='timestamp', limit=25)
    def details(self):
       """display IRC messages in a paged table""" 
       log.debug("######################## Happy TurboGears IRC Responding For Duty")
       
       ircq = session.query(IRCMessage)
       messages = SelectResults(ircq)
       return { 'request': None, 'form' : self.IRCSearchForm, 'messages' : messages,
                'list': self.IRCMessageGrid }

    @expose(template="honeysnap_web.templates.irc_summary")
    def summary(self):
        """Summary of IRC stats"""
        return { 'request': None, 'form' : self.IRCSearchForm }

class IPSearch(controllers.Controller):
    """Provides IP search stuff"""

    #require = identity.in_group('admin')

    IPSearchForm = TableForm(fields=[ TextField("ipaddr") ], submit_text="Search")

    @expose(template="honeysnap_web.templates.ip_search")
    def index(self):
        """Basic IP search page"""
        return dict(ip_search_form = IPSearch.IPSearchForm)

    @expose(template="honeysnap_web.templates.ip_results")
    @error_handler(index)    
    def by_ip(self, ipaddr):
        """returns details for given IPs"""
        return { 'request': None}

    @expose(template="honeysnap_web.templates.ip_summary")
    def summary(self):
        """summmary of IP stats"""
        return { 'request': None }

       
class Root(controllers.RootController):  

    irc = IRCMessages()
    ip = IPSearch() 
    sebek = SebekMessages() 
    flows = Flows()
    
    @expose(template="honeysnap_web.templates.welcome")
    # @identity.require(identity.in_group("admin"))
    def index(self):
        flows = session.query(Flow).count()
        sebek = session.query(Sebek).count()
        irc = session.query(IRCMessage).count()      
        honeypots = session.query(Honeypot).count()
        log.debug("Happy TurboGears Controller Responding For Duty")
        return dict(request=None, now=time.ctime(), flows=flows,
            sebek=sebek, irc=irc, honeypots=honeypots)

    @expose(template="honeysnap_web.templates.login")
    def login(self, forward_url=None, previous_url=None, *args, **kw):

        if not identity.current.anonymous \
            and identity.was_login_attempted() \
            and not identity.get_identity_errors():
            raise redirect(forward_url)

        forward_url=None
        previous_url= request.path

        if identity.was_login_attempted():
            msg=_("The credentials you supplied were not correct or "
                   "did not grant access to this resource.")
        elif identity.get_identity_errors():
            msg=_("You must provide your credentials before accessing "
                   "this resource.")
        else:
            msg=_("Please log in.")
            forward_url= request.headers.get("Referer", "/")
            
        response.status=403
        return dict(message=msg, previous_url=previous_url, logging_in=True,
                    original_parameters=request.params,
                    forward_url=forward_url)

    @expose()
    def logout(self):
        identity.current.logout()
        raise redirect("/")
