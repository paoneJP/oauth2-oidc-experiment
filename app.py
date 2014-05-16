#! /usr/bin/python

import logging
from logging.handlers import TimedRotatingFileHandler
import json

import bottle
from bottle import route, get, post, view
from beaker.middleware import SessionMiddleware

from oauth2py.client import *


app = bottle.app()
session_opts = {
    'session.type': 'file',
    'session.data_dir': './sessions',
    'session.cookie_expires': True,
    'session.secure': True,
    'session.auto': True
}
app = SessionMiddleware(app, session_opts)

logger = logging.getLogger('wsgi')
logger.addHandler(TimedRotatingFileHandler('logs/access.log',
                                           'midnight',
                                           backupCount=90))


MYSERVER = 'https://{{{_YOUR_SERVER_FQDN_}}}'


server = ServerConfig(
             authorization_endpoint= \
                 'https://accounts.google.com/o/oauth2/auth',
             token_endpoint='https://accounts.google.com/o/oauth2/token',
             token_endpoint_auth_methods_supported='client_secret_post',
             userinfo_endpoint= \
                 'https://www.googleapis.com/plus/v1/people/me/openIdConnect'
         )
client = ClientConfig(
             client_id='{{{_CLINET_ID_FOR_GOOGLE_}}}',
             client_secret='{{{_CLIENT_SECRET_FOR_GOOGLE_}}}',
             redirect_uri=MYSERVER+'/authn/google/cb'
         )
google_code_flow = AuthorizationCodeFlow(server, client)


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
             client_id='{{{_CLIENT_ID_FOR_YCONNECT_}}}',
             client_secret='{{{_CLIENT_SECRET_FOR_YCONNECT_}}}',
             redirect_uri=MYSERVER+'/authn/yconnect/cb'
         )
yconnect_code_flow = AuthorizationCodeFlow(server, client)



def check_authn(callback):
    def wrapper(*args, **kwargs):
        session = bottle.request.environ['beaker.session']
        if not ('authn' in session and session['authn']):
            bottle.redirect('/authn')
        return callback(*args, **kwargs)
    return wrapper

def pass_session(callback):
    def wrapper(*args, **kwargs):
        kwargs['session'] = bottle.request.environ['beaker.session']
        return callback(*args, **kwargs)
    return wrapper

bottle.install(check_authn)
bottle.install(pass_session) # pass_session plugin must be installed last



@get('/app')
@view('app.tmpl')
def app_get(session):
    return dict(userinfo=session['userinfo'],
                context=session['oauth2_context'])


@get('/authn', skip=check_authn)
@view('authn.tmpl')
def authn_get(session):
    if not 'oauth2_context' in session:
        ctx = Context(target_link_uri=MYSERVER+'/app')
        session['oauth2_context'] = ctx

@get('/authn/logout')
def authn_logout(session):
    del(session['authn'])
    del(session['oauth2_context'])
    bottle.redirect(MYSERVER+'/app')


def redirect_to_auth_uri(session, flow, scope=None, **kwargs):
    ctx = session['oauth2_context']
    r = flow.auth_uri(ctx, scope, **kwargs)
    bottle.redirect(r)

def process_authorization_response(session, flow):
    ctx = session['oauth2_context']
    q = bottle.request.query_string
    try:
        flow.proc_response(ctx, q)
    except OAuth2FlowError as e:
        m = 'error occurred in authorization process'
        bottle.abort(400, m)
    try:
        r = oauth2urlopen(ctx, flow.server.userinfo_endpoint)
        session['userinfo'] = json.loads(r.read())
    except (OAuth2URLOpenError, ValueError) as exp:
        m = 'error occurred in authorization process'
        bottle.abort(400, m)
    session['authn'] = True
    bottle.redirect(ctx.target_link_uri)


@get('/authn/google', skip=check_authn)
def authn_google_get(session):
    redirect_to_auth_uri(session, google_code_flow, scope='email')

@get('/authn/google/cb', skip=check_authn)
def authn_google_cb_get(session):
    process_authorization_response(session, google_code_flow)


@get('/authn/yconnect', skip=check_authn)
def authn_yconnect_get(session):
    redirect_to_auth_uri(session, yconnect_code_flow, scope='email')

@get('/authn/yconnect/cb', skip=check_authn)
def authn_yconnect_cb_get(session):
    process_authorization_response(session, yconnect_code_flow)


bottle.run(reloader=True, debug=True,
           app=app, host='0.0.0.0', port=443, server='paste',
           ssl_pem='certs/server.pem', quiet=True)
