from turbogears import controllers, expose
from model import *
from turbogears import identity, redirect
from turbogears.database import session
from cherrypy import request, response
# from honeysnap_web import json
# import logging
# log = logging.getLogger("honeysnap_web.controllers")

class Root(controllers.RootController):
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
