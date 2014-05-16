import sys
import re
import base64


__all__ = ['urlopen', 'parse_qs', 'Request', 'urlencode', 'URLError']


if sys.version_info[0] == 2:
    from urllib2 import urlopen as _urlopen
    from urllib2 import Request
    from urllib2 import URLError
    from urllib import urlencode
    from urlparse import parse_qs as _parse_qs
else:
    from urllib.request import urlopen as _urlopen
    from urllib.request import Request
    from urllib.request import URLError
    from urllib.parse import urlencode
    from urllib.parse import parse_qs as _parse_qs


def urlopen(url, data=None, *args, **kwargs):
    if not isinstance(url, Request):
        url = Request(url, data)
        data = None
    if 'basic_auth' in kwargs:
        if kwargs['basic_auth']:
            a = base64.b64encode(':'.join(kwargs['basic_auth']))
            url.add_header('Authorization', 'Basic '+a)
        del(kwargs['basic_auth'])
    if 'authorization' in kwargs:
        if kwargs['authorization']:
            url.add_header('Authorization', kwargs['authorization'])
        del(kwargs['authorization'])
    if sys.version_info[0] == 2:
        url.add_header('Host', url.get_origin_req_host())
        return _urlopen(url, data, *args, **kwargs)
    else:
        url.add_header('Host', url.origin_req_host)
        kwargs['cadefaults'] = True
        return _urlopen(url, data, *args, **kwargs)


def parse_qs(*args, **kwargs):
    d = _parse_qs(*args, **kwargs)
    r = {}
    for k in d:
        r[k] = d[k][0]
    return r
