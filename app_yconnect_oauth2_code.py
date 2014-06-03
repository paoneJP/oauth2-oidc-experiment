import json

import bottle
from bottle import view

from app_config import app_config
from oauth2py.client import *
from oauth2py.common import state


MOUNT_PREFIX = '/yconnect/oauth2/code'


server = ServerConfig(
             authorization_endpoint= \
                 'https://auth.login.yahoo.co.jp/yconnect/v1/authorization',
             token_endpoint= \
                 'https://auth.login.yahoo.co.jp/yconnect/v1/token',
             userinfo_endpoint= \
                 'https://userinfo.yahooapis.jp/yconnect/v1/attribute?' \
                 'schema=openid'
         )
client = ClientConfig(
             client_id= \
                 app_config['yconnect_server_side_app']['client_id'],
             client_secret= \
                 app_config['yconnect_server_side_app']['client_secret'],
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
