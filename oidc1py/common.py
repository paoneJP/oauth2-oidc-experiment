from oauth2py.common import xdict, state, random_string


__all__ = ['xdict', 'state', 'nonce']


def nonce(n=12):
    return random_string(n)
