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
                   '_signature',
                   '_raw_header',
                   '_raw_payload']

    def __init__(self, token=None):
        xdict.__init__(self)
        self.header = _IDTokenHeader()
        self.payload = _IDTokenPayload()
        if token:
            self._from_jwt(token)

    def _from_jwt(self, jwt):
        h, p, s = str(jwt).split('.', 2)
        self._raw_header = h
        self._raw_payload = p
        self._signature = s

        d = json.loads(base64.urlsafe_b64decode(h+'=='))
        self.header.update(d)
        d = json.loads(base64.urlsafe_b64decode(p+'=='))
        self.payload.update(d)

    def raw(self):
        rv = self._raw_header + '.' + self._raw_payload + '.' + self._signature
        return rv
