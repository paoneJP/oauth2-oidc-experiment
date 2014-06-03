import json

import bottle
from bottle import view

from app_config import app_config
from oidc1py.client import *
from oidc1py.common import state, nonce
from oauth2py.client import oauth2urlopen


MOUNT_PREFIX = '/yconnect/oidc/code'


def yconnect_auth_uri_customize(context, param):
    param.response_type = param.response_type + ' id_token'


op = OPConfig(
         authorization_endpoint= \
             'https://auth.login.yahoo.co.jp/yconnect/v1/authorization',
         token_endpoint= \
             'https://auth.login.yahoo.co.jp/yconnect/v1/token',
         userinfo_endpoint= \
             'https://userinfo.yahooapis.jp/yconnect/v1/attribute?' \
             'schema=openid'
     )
rp = RPConfig(
         client_id= \
             app_config['yconnect_server_side_app']['client_id'],
         client_secret= \
             app_config['yconnect_server_side_app']['client_secret'],
         redirect_uri= \
             app_config['server']['server']+MOUNT_PREFIX+'/authn/cb'
     )
flow = AuthorizationCodeFlow(op, rp)
flow.add_hook('auth_uri_customize_hook', yconnect_auth_uri_customize)


app = bottle.Bottle()


@app.get('/authn')
def authn_get():
    session = bottle.request.environ['beaker.session']
    ctx = Context(target_link_uri=MOUNT_PREFIX+'/show')
    session['context'] = ctx
    r = flow.auth_uri(ctx, 'email', state=state(), nonce=nonce())
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
