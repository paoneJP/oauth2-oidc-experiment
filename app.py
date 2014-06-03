#! /usr/bin/python

import logging
from logging.handlers import TimedRotatingFileHandler
import json

import bottle
from bottle import route, get, post, view
from beaker.middleware import SessionMiddleware

from app_config import app_config


bottle_app = bottle.app()

session_opts = {
    'session.type': 'file',
    'session.data_dir': './sessions',
    'session.cookie_expires': True,
    'session.secure': True,
    'session.auto': True
}
app = SessionMiddleware(bottle_app, session_opts)

logger = logging.getLogger('wsgi')
logger.addHandler(TimedRotatingFileHandler('logs/access.log',
                                           'midnight',
                                           backupCount=90))


@get('/')
@view('root.html')
def root_get():
    pass


import app_google_oauth2_code
bottle_app.mount('/google/oauth2/code', app_google_oauth2_code.app)


import app_google_oidc_code
bottle_app.mount('/google/oidc/code', app_google_oidc_code.app)


import app_yconnect_oauth2_code
bottle_app.mount('/yconnect/oauth2/code', app_yconnect_oauth2_code.app)


import app_yconnect_oidc_code
bottle_app.mount('/yconnect/oidc/code', app_yconnect_oidc_code.app)


bind_ip = app_config['server']['bind_ip']
bind_port = app_config['server']['bind_port']
if app_config['server']['use_ssl']:
    cert = app_config['server']['server_cert']
else:
    cert = None

bottle.run(reloader=True, debug=True,
           app=app, host=bind_ip, port=bind_port, server='paste',
           ssl_pem=cert, quiet=True)
