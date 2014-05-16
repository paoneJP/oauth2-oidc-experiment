import time
import json

from common import xdict
from xurllib import *


__all__ = ['ClientConfig', 'ServerConfig', 'Context',
           'AuthorizationCodeFlow', 'ImplicitFlow',
           'oauth2urlopen',
           'OAuth2FlowError', 'OAuth2URLOpenError']



class ClientConfig(xdict):

    _attributes = ['client_id',
                   'client_secret',
                   'redirect_uri',
                   'fragment_hander_uri']


class ServerConfig(xdict):

    _attributes = ['authorization_endpoint',
                   'token_endpoint',
                   ('token_endpoint_auth_methods_supported',
                        ['client_secret_basic'])]


class Context(xdict):

    _attributes = ['state',
                   'access_token',
                   'token_type',
                   'expires_at',
                   'refresh_token',
                   'target_link_uri']


class _BaseFlowClass(object):

    def __init__(self, server, client):
        self.server = server
        self.client = client

    def auth_uri(self, context, response_type, scope=None, state=None,
                 **kwargs):
        if state:
            context.state = state
        p = xdict(response_type=response_type,
                  client_id=self.client.client_id,
                  redirect_uri=self.client.redirect_uri,
                  scope=scope,
                  state=context.state)
        for k in kwargs:
            p[k] = kwargs[k]
        p = urlencode(p.to_dict())
        rv = self.server.authorization_endpoint + '?' + p
        return rv

    def proc_response(self, context, query):
        param = parse_qs(query)
        if context.state:
            if not context.state == param['state']:
                e = 'state value is not match.'
                raise OAuth2FlowError(e)
        if 'error' in param:
            return self._proc_error_response(context, param)
        self._proc_ok_response(context, param)

    def _proc_error_response(self, context, param):
        e = 'authorization error.'
        raise OAuth2FlowError(e, param)

    def _proc_ok_response(self, context, param):
        pass


class AuthorizationCodeFlow(_BaseFlowClass):

    def auth_uri(self, context, scope=None, state=None, **kwargs):
        return _BaseFlowClass.auth_uri(self, context, 'code', scope, state,
                                       **kwargs)

    def _proc_ok_response(self, context, param):
        a = None
        p = xdict(grant_type='authorization_code',
                  code=param['code'],
                  redirect_uri=self.client.redirect_uri)
        m = self.server.token_endpoint_auth_methods_supported
        if m == 'client_secret_basic' or 'client_secret_basic' in m:
            a = (self.client.client_id, self.client.client_secret)
        elif m == 'client_secret_post' or 'client_secret_post' in m:
            p['client_id'] = self.client.client_id
            p['client_secret'] = self.client.client_secret
        else:
            e = 'unsupported token endpoint auth method'
            raise OAuth2FlowError(e)

        try:
            r = urlopen(self.server.token_endpoint, urlencode(p),
                        basic_auth=a).read()
        except URLError as exp:
            e = 'error occurred while requesting to token endpoint.'
            raise OAuth2FlowError(e, exp)

        try:
            r = json.loads(r)
            context.access_token = r['access_token']
            context.token_type = r['token_type']
            context.expires_at = time.time() + int(r['expires_in'])
        except (ValueError, KeyError) as exp:
            e = 'invalid response from token endpoint.'
            raise OAuth2FlowError(e, exp)

        try:
            context.refresh_token = r['refresh_token']
        except KeyError:
            pass


class ImplicitFlow(_BaseFlowClass):
    pass


def oauth2urlopen(context, url, data=None, *args, **kwargs):
    if context.token_type.lower() == 'bearer':
        a = 'Bearer ' + context.access_token
        try:
            r = urlopen(url, data, authorization=a, *args, **kwargs)
        except URLError as exp:
            e = 'error occurred while opening url.'
            raise OAuth2URLOpenError(e, exp)
    else:
        e = 'unsupported token type.'
        raise OAuth2URLOpenError(e)
    if r.getcode() != 200:
        e = 'server returned bad status code'
        raise OAuth2URLOpenError(e, r.getcode())
    return r



class OAuth2FlowError(Exception):
    pass


class OAuth2URLOpenError(Exception):
    pass
