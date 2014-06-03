import json

import oauth2py.client
from oidc1py.model import IDToken
from oauth2py.xurllib import *


__all__ = ['RPConfig', 'OPConfig', 'Context',
           'AuthorizationCodeFlow', 'ImplicitFlow',
           'get_openid_configuration']


class RPConfig(oauth2py.client.ClientConfig):
    pass


class OPConfig(oauth2py.client.ServerConfig):

    _attributes = oauth2py.client.ServerConfig._attributes + \
                      ['issuer',
                       'jwks_uri',
                       ('response_modes_supported', ['query', 'fragment']),
                       ('grant_types_supported',
                            ['authorization_code', 'implicit']),
                       ('claim_types_supported', 'normal'),
                       ('claims_parameter_supported', False),
                       ('request_parameter_supported', False),
                       ('request_uri_parameter_supported', True),
                       ('require_request_uri_registration', False)]


class Context(oauth2py.client.Context):

    _attributes = oauth2py.client.Context._attributes + \
                      ['nonce',
                       'id_token']


class AuthorizationCodeFlow(oauth2py.client.AuthorizationCodeGrant):

    def __init__(self, server, client):
        oauth2py.client.AuthorizationCodeGrant.__init__(self, server, client)
        self.add_hook('after_token_parse_hook', self._parse_id_token)

    def auth_uri(self, context, scope, state=None, nonce=None, **kwargs):
        if nonce:
            context.nonce = nonce
        s = scope.split()
        if not 'openid' in s:
            s.append('openid')
        scope = ' '.join(s)
        rv = oauth2py.client.AuthorizationCodeGrant.auth_uri(self, context,
                 scope=scope, state=state, nonce=nonce, **kwargs)
        return rv

    def _parse_id_token(self, context, param):
        if 'id_token' in param:
            t = IDToken(param['id_token'].encode())
            context.id_token = t


class ImplicitFlow(oauth2py.client.ImplicitGrant):
    pass


def get_openid_configuration(server):
    if not server.endswith('/.well-known/openid-configuration'):
        server = server + '/.well-known/openid-configuration'
    j = urlopen(server).read()
    d = json.loads(j)
    rv = OPConfig(d)
    return rv
