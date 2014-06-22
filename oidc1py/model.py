import json
import base64

from oauth2py.common import xdict


__all__ = ['IDToken']


class _IDTokenHeader(xdict):

    _attributes = ['typ',
                   'alg']


class _IDTokenPayload(xdict):

    _attributes = ['iss',
                   'sub',
                   'aud',
                   'exp',
                   'iat']


class IDToken(xdict):

    _attributes = ['header',
                   'payload',
                   '_raw_token']

    def __init__(self, token=None):
        xdict.__init__(self)
        self.header = _IDTokenHeader()
        self.payload = _IDTokenPayload()
        if token:
            self._from_jwt(token)

    def _from_jwt(self, jwt):
        self._raw_token = jwt

        h, p, s = str(jwt).split('.', 2)
        d = json.loads(base64.urlsafe_b64decode(h+'=='))
        self.header.update(d)
        d = json.loads(base64.urlsafe_b64decode(p+'=='))
        self.payload.update(d)

    def raw(self):
        return self._raw_token
