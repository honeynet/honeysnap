from turbogears import controllers, expose
from model import *
from turbogears import identity, redirect
from turbogears import validators, validate, error_handler, paginate
from turbogears.database import session
from turbogears.widgets import PaginateDataGrid, TableForm, TextField 
from turbogears.widgets.big_widgets import CalendarDateTimePicker
from cherrypy import request, response
# from honeysnap_web import json
# import logging
# log = logging.getLogger("honeysnap_web.controllers")
        
def irc_url_helper(type, field, text):
    if type == 'details':
        url = turbogears.url('/irc/details')
    else:
        url = turbogears.url('/irc/summary')
    text = urllib.quote(text)
    link = ElementTree.Element('a', href='%s?%s=%s' % (url, field, text))
    link.text = urllib.unquote(text)
    return link
               
class IRCMessages(controllers.Controller, identity.SecureResource):
    """IRC output"""

    #require = identity.in_group("admin")

    IRCMessageGrid = PaginateDataGrid(
        fields=[                                                     
            PaginateDataGrid.Column('timestamp', 'timestamp', 'Time',
                            options=dict(sortable=True)),        
            PaginateDataGrid.Column('from_id', 'irc_from', 'from',
                                options=dict(sortable=True)),        
            PaginateDataGrid.Column('text', 'text', 'Text')                                
            ],
        )

    IRCSearchForm = TableForm( fields=[ TextField(name="text",     label="Text"),
                                                TextField(name="channel",  label="Channel"),
                                                TextField(name="IRC From", label="From"),
                                                TextField(name="IRC To",   label="To"),
                                                TextField(name="command",  label="Command"),
                                                TextField(name="Source", validator=validators.Regex(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')),
                                                TextField(name="Destination", validator=validators.Regex(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')),
                                                CalendarDateTimePicker(name="starttime",
                                                                label="Start time",
                                                                validator=validators.DateTimeConverter(),
                                                                default=datetime(1990,1,1,0,0)),
                                                CalendarDateTimePicker(name="endtime",
                                                                label="End time",
                                                                default=datetime.now(),
                                                                validator=validators.DateTimeConverter())
                                                ],
                                       submit_text="Search")  
                                       
    @expose(template="honeysnap_web.templates.irc_details") 
    @paginate('messages', default_order='timestamp')
    def details(self, order='timestamp', page=0, stride=20, **fields):
       """display IRC messages in a paged table""" 
       ircq = session.query(IRCMessage)
       messages = SelectResults(ircq)
       return { 'request': None, 'form' : self.IRCSearchForm, 'messages' : messages,
                'list': self.IRCMessageGrid }

    @expose(template="honeysnap_web.templates.irc_summary")
    def summary(self, **fields):
        """Summary of IRC stats"""
        return { 'request': None, 'form' : self.IRCSearchForm }

class IPSearch(controllers.Controller, identity.SecureResource):
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
        return {}

    @expose(template="honeysnap_web.templates.ip_summary")
    def summary(self):
        """summmary of IP stats"""
        return { 'request': None }

       

class Root(controllers.RootController):  
    
    irc = IRCMessages()
    ip = IPSearch()
    
    @expose(template="honeysnap_web.templates.welcome")
    # @identity.require(identity.in_group("admin"))
    def index(self):
        import time    
        flow_count = session.query(Flow).count()
        # log.debug("Happy TurboGears Controller Responding For Duty")
        return dict(now=time.ctime(), flow_count=flow_count)

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
