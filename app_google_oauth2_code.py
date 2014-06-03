import json

import bottle
from bottle import view

from app_config import app_config
from oauth2py.client import *
from oauth2py.common import state


MOUNT_PREFIX = '/google/oauth2/code'


server = ServerConfig(
             authorization_endpoint= \
                 'https://accounts.google.com/o/oauth2/auth',
             token_endpoint='https://accounts.google.com/o/oauth2/token',
             token_endpoint_auth_methods_supported='client_secret_post',
             userinfo_endpoint= \
                 'https://www.googleapis.com/plus/v1/people/me/openIdConnect'
         )
client = ClientConfig(
             client_id= \
                 app_config['google_web_application_type']['client_id'],
             client_secret= \
                 app_config['google_web_application_type']['client_secret'],
             redirect_uri= \
                 app_config['server']['server']+MOUNT_PREFIX+'/authn/cb'
         )
flow = AuthorizationCodeGrant(server, client)


app = bottle.Bottle()


@app.get('/authn')
def authn_get():
    session = bottle.request.environ['beaker.session']
    ctx = Context(target_link_uri=MOUNT_PREFIX+'/show')
    session['context'] = ctx
    r = flow.auth_uri(ctx, 'email', state=state())
    session['auth_uri'] = r
    bottle.redirect(r)


@app.get('/authn/cb')
def authn_cb_get():
    session = bottle.request.environ['beaker.session']
    ctx = session['context']

    query = bottle.request.query_string
    flow.proc_response(ctx, query)
    r = oauth2urlopen(ctx, flow.server.userinfo_endpoint)
    session['userinfo'] = json.loads(r.read())

    bottle.redirect(ctx.target_link_uri)


@app.get('/show')
@view('show.tmpl')
def show_get():
    session = bottle.request.environ['beaker.session']
    if not 'context' in session:
        bottle.redirect(MOUNT_PREFIX+'/authn')
    auth_uri = session['auth_uri']
    context = json.dumps(session['context'].to_dict(), indent=2)
    userinfo = json.dumps(session['userinfo'], indent=2)
    session.delete()
    return dict(auth_uri=auth_uri, context=context, userinfo=userinfo)
