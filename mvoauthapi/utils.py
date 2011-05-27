import re


def parse_www_authenticate(string):
    """
    Parse a WWW-Authenticate header. Returns a tuple of length 2
    containing the authentication mechanism (str) and the parameters
    (dict: str -> str).
    """
    parts = re.split(r'\s+', string, 1)
    mechanism = parts[0]
    if len(parts) > 1:
        params = re.split('\s*,\s*', parts[1])
        params = dict(p.split('=', 1) if '=' in p else (p, None) for p in params)
    else:
        params = {}
    return mechanism, params
