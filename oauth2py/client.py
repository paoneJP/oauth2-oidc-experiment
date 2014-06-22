import time
import json

from common import xdict
from xurllib import *


__all__ = ['ClientConfig', 'ServerConfig', 'Context',
           'AuthorizationCodeGrant', 'ImplicitGrant',
           'oauth2urlopen']


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


class _Hook(xdict):

    _attributes = [('auth_uri_customize_hook', []),
                   ('before_token_parse_hook', []),
                   ('after_token_parse_hook', [])]


class _BaseFlowClass(object):

    def __init__(self, server, client):
        self.server = server
        self.client = client
        self._hook = _Hook()

    def auth_uri(self, context, response_type, scope=None, state=None,
                 **kwargs):
        if state:
            context.state = state
        param = xdict(response_type=response_type,
                      client_id=self.client.client_id,
                      redirect_uri=self.client.redirect_uri,
                      scope=scope,
                      state=context.state)
        for k in kwargs:
            param[k] = kwargs[k]

        self._call_hook('auth_uri_customize_hook', context, param)

        p = urlencode(param.to_dict())
        rv = self.server.authorization_endpoint + '?' + p
        return rv

    def proc_response(self, context, param):
        if not isinstance(param, dict):
            param = parse_qs(param)

        if 'error' in param:
            raise OAuth2AuthorizationError(param)
        if context.state:
            if not context.state == param['state']:
                raise OAuth2StateValueDoesNotMatchError()

        self._call_hook('before_token_parse_hook', context, param)

        if 'access_token' in param:
            context.access_token = param['access_token']
        if 'token_type' in param:
            context.token_type = param['token_type']
        if 'refresh_token' in param:
            context.refresh_token = param['refresh_token']
        if 'expires_in' in param:
            context.expires_at = int(time.time()) + int(param['expires_in'])

        self._call_hook('after_token_parse_hook', context, param)

    def add_hook(self, name, func):
        self._hook[name].append(func)

    def _call_hook(self, name, *args, **kwargs):
        for f in self._hook[name]:
            if type(f) == 'instancemethod':
                f(self, *args, **kwargs)
            else:
                f(*args, **kwargs)


class AuthorizationCodeGrant(_BaseFlowClass):

    def __init__(self, server, client):
        _BaseFlowClass.__init__(self, server, client)
        self.add_hook('before_token_parse_hook',
                      self._get_token_from_token_endpoint)

    def auth_uri(self, context, scope=None, state=None, **kwargs):
        rv = _BaseFlowClass.auth_uri(self, context, 'code', scope, state,
                                     **kwargs)
        return rv

    def _get_token_from_token_endpoint(self, context, param):
        cred = None
        p = xdict(grant_type='authorization_code',
                  code=param['code'],
                  redirect_uri=self.client.redirect_uri)
        methods = self.server.token_endpoint_auth_methods_supported
        if 'client_secret_basic' in methods:
            cred = (self.client.client_id, self.client.client_secret)
        elif 'client_secret_post' in methods:
            p['client_id'] = self.client.client_id
            p['client_secret'] = self.client.client_secret
        else:
            raise OAuth2UnsupportedAuthMethodError()

        r = urlopen(self.server.token_endpoint, urlencode(p), basic_auth=cred)
        d = json.loads(r.read())

        param.clear()
        param.update(d)


class ImplicitGrant(_BaseFlowClass):
    pass


def oauth2urlopen(context, url, data=None, *args, **kwargs):
    if context.token_type.lower() == 'bearer':
        a = 'Bearer ' + context.access_token
        rv = urlopen(url, data, authorization=a, *args, **kwargs)
    else:
        raise OAuth2UnsupportedTokenTypeError()
    return rv


class OAuth2ClientError(Exception):
    pass

class OAuth2AuthorizationError(OAuth2ClientError):
    pass

class OAuth2StateValueDoesNotMatchError(OAuth2ClientError):
    pass

class OAuth2UnsupportedAuthMethodError(OAuth2ClientError):
    pass

class OAuth2UnsupportedTokenTypeError(OAuth2ClientError):
    pass
