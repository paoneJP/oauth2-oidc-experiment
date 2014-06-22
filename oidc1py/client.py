import json
import base64
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import HMAC, SHA256

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


class _BaseFlowMixIn:

    def __init__(self, server, client):
        self.jwks = {}

    def verify_id_token(self, context, freshness=None):
        token = context.id_token
        if not self._verify_signature(context):
            return False
        if not (token.payload.iss == self.server.issuer or \
                token.payload.aud == self.client.client_id or \
                token.payload.exp >= time.time()):
            return False
        if freshness and not token.payload.iat >= time.time() - freshness:
            return False
        if 'nonce' in context and not token.payload.nonce == context.nonce:
            return False
        return True

    def _verify_signature(self, context):
        f = self.__getattribute__('_verify_signature_'
                                  + context.id_token.header.alg.upper())
        rv = f(context)
        return rv

    def _verify_signature_RS256(self, context):
        token = context.id_token
        if not token.header.kid in self.jwks:
            self._update_jwks()
            if not token.header.kid in self.jwks:
                return False
        k = self.jwks[token.header.kid]
        p = PKCS1_v1_5.new(k['key'])
        t = token.raw().rsplit('.', 1)
        s = base64.urlsafe_b64decode(str(t[1])+'==')
        rv = p.verify(SHA256.new(t[0]), s)
        return rv

    def _update_jwks(self):
        if not self.server.jwks_uri:
            return
        r = urlopen(self.server.jwks_uri)
        d = json.loads(r.read())
        keys = {}
        for k in d['keys']:
            if k['kty'].upper() == 'RSA':
                n = bytes_to_long(base64.urlsafe_b64decode(str(k['n'])+'=='))
                e = bytes_to_long(base64.urlsafe_b64decode(str(k['e'])+'=='))
                r = RSA.construct((n,e))
                k['key'] = r
            keys[k['kid']] = k
        self.jwks = keys

    def _verify_signature_HS256(self, context):
        token = context.id_token
        t = token.raw().rsplit('.', 1)
        h = HMAC.new(self.client.client_secret, t[0], SHA256)
        s = base64.urlsafe_b64decode(str(t[1])+'==')
        if h.digest() == s:
            return True
        return False


class AuthorizationCodeFlow(oauth2py.client.AuthorizationCodeGrant,
                            _BaseFlowMixIn):

    def __init__(self, server, client):
        oauth2py.client.AuthorizationCodeGrant.__init__(self, server, client)
        _BaseFlowMixIn.__init__(self, server, client)
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
            t = IDToken(str(param['id_token']))
            context.id_token = t


class ImplicitFlow(oauth2py.client.ImplicitGrant, _BaseFlowMixIn):
    pass


def get_openid_configuration(server):
    if not server.endswith('/.well-known/openid-configuration'):
        server = server + '/.well-known/openid-configuration'
    r = urlopen(server)
    d = json.loads(r.read())
    rv = OPConfig(d)
    return rv
