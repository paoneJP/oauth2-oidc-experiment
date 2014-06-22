import json

import bottle
from bottle import view

from app_config import app_config
from oidc1py.client import *
from oidc1py.common import state, nonce
from oauth2py.client import oauth2urlopen


MOUNT_PREFIX = '/google/oidc/code'


def google_auth_uri_customize(context, param):
    del(param.nonce)
    del(context.nonce)


op = get_openid_configuration('https://accounts.google.com')
rp = RPConfig(
         client_id= \
             app_config['google_web_application_type']['client_id'],
         client_secret= \
             app_config['google_web_application_type']['client_secret'],
         redirect_uri= \
             app_config['server']['server']+MOUNT_PREFIX+'/authn/cb'
     )
flow = AuthorizationCodeFlow(op, rp)
flow.add_hook('auth_uri_customize_hook', google_auth_uri_customize)


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

    session['id_token_verified'] = flow.verify_id_token(ctx)

    bottle.redirect(ctx.target_link_uri)


@app.get('/show')
@view('show_oidc.tmpl')
def show_get():
    session = bottle.request.environ['beaker.session']
    if not 'context' in session:
        bottle.redirect(MOUNT_PREFIX+'/authn')
    auth_uri = session['auth_uri']
    context = json.dumps(session['context'].to_dict(), indent=2)
    userinfo = json.dumps(session['userinfo'], indent=2)
    id_token_verified = session['id_token_verified']
    session.delete()
    return dict(auth_uri=auth_uri, context=context, userinfo=userinfo,
                id_token_verified=id_token_verified)
