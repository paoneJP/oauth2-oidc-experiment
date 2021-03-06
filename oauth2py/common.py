import json
import string
from copy import copy
from Crypto.Random import random


__all__ = ['xdict', 'state']


class xdict(dict):

    _attributes = []

    def __init__(self, *args, **kwargs):
        for k in self._attributes:
            if isinstance(k, tuple):
                self[k[0]] = copy(k[1])
            else:
                self[k] = None
        dict.__init__(self, *args, **kwargs)

    def to_json(self):
        d = self.to_dict()
        rv = json.dumps(d)
        return rv

    def to_dict(self):
        rv = {}
        for k in self:
            if k.startswith('_'):
                continue
            if self[k]:
                if isinstance(self[k], xdict):
                    rv[k] = self[k].to_dict()
                else:
                    rv[k] = self[k]
        return rv

    def __getattr__(self, k):
        if k in self:
            return self[k]
        e = "'{}' object has no attribute '{}'" \
                .format(self.__class__.__name__, k)
        raise AttributeError(e)

    def __setattr__(self, k, v):
        if k.startswith('_'):
            dict.__setattr__(self, k, v)
        if k in self:
            self[k] = v
            return
        e = "'{}' object has no attribute '{}'" \
                .format(self.__class__.__name__, k)
        raise AttributeError(e)

    def __delattr__(self, k):
        if k in self:
            del(self[k])
            return
        e = "'{}' object has no attribute '{}'" \
                .format(self.__class__.__name__, k)
        raise AttributeError(e)


def random_string(n):
    rv = ''.join([random.choice(string.ascii_letters+string.digits) \
                     for x in range(n)])
    return rv


def state(n=8):
    return random_string(n)
