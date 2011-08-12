#!/usr/bin/env python

import urllib

from oauth2 import Client, Request, Consumer, Token

import errors

from utils import parse_www_authenticate


class ApiClient(object):
    """
    OAuth client for the Mobile Vikings API.

    Read README.rst for a brief explanation of the OAuth protocol and a
    tutorial for this client.

    A list of available API methods, their parameters and return values
    can be found here: https://mobilevikings.com/api/2.0/doc/
    """
    PROTOCOL = 'https'
    HOST = 'mobilevikings.com'
    PORT = 443
    VERSION = '2.0'
    FORMAT = 'json'

    PATH = '/api/' + VERSION + '/oauth/'
    BASE_URL = PROTOCOL + '://' + HOST + ':%d' % PORT + PATH
    REQUEST_TOKEN_URL = BASE_URL + 'request_token/'
    AUTHORIZE_TOKEN_URL = BASE_URL + 'authorize/'
    ACCESS_TOKEN_URL = BASE_URL + 'access_token/'

    def __init__(self, consumer_key, consumer_secret, format=FORMAT):
        """
        Construct a new API client instance.

        ``consumer_key``: key of the application consuming data from the API.
        ``consumer_secret``: secret corresponding to the consumer key.
        ``format``: output format of the API. Should be one of the following
            strings: 'json', 'xml', 'yaml', 'pickle'.

        You can find the consumer key and secret on your account settings
        page: https://mobilevikings.com/account/settings/
        """
        self.consumer = Consumer(consumer_key, consumer_secret)
        self.client = Client(self.consumer)
        self.request_token = None
        self.access_token = None
        self.format = format

    @staticmethod
    def _detect_errors(response, content):
        """ Examine response and raise appropriate exception if necessary. """
        lower = content.lower()

        if response['status'] == '400' and 'invalid consumer' in lower:
            raise errors.InvalidConsumer(response, content)
        if response['status'] == '400' and 'invalid request token' in lower:
            raise errors.RequestTokenExpired(response, content)
        if response['status'] == '400' and 'could not verify' in lower:
            raise errors.AccessDenied(response, content)
        if response['status'] == '400' and 'invalid oauth verifier' in lower:
            raise errors.InvalidVerifier(response, content)
        if response['status'] == '400' and 'missing oauth parameters' in lower:
            raise errors.MissingParameters(response, content)
        if response['status'] == '403' and 'xauth not allowed for this consumer' in lower:
            raise errors.XAuthNotAllowed(response, content)
        if response['status'] == '403' and 'xauth username/password combination invalid' in lower:
            raise errors.XAuthAccessDenied(response, content)
        if response['status'] == '404':
            raise errors.InvalidMethod(response, content)
        if response['status'] == '401' and 'www-authenticate' in response:
            www_auth = response['www-authenticate']
            mech, params = parse_www_authenticate(www_auth)
            if mech == 'OAuth' and params.get('realm') == '"Mobile Vikings"':
                raise errors.AccessTokenExpired(response, content)
        if response['status'].startswith('4') or response['status'].startswith('5'):
            raise errors.ApiServerError(response, content)

    def _request(self, *args, **kwargs):
        """ Perform an OAuth client request with error detection. """
        response, content = self.client.request(*args, **kwargs)
        ApiClient._detect_errors(response, content)
        return response, content

    def fetch_request_token(self, callback='oob'):
        """
        Fetch a request token.

        ``callback`` (optional): URL the user will be redirected to
        when she has granted access. Pass 'oob' to if you want the Mobile
        Vikings site to show the verification code without a redirect.

        Returns a :class:`oauth2.Token` instance.
        """
        args = {'oauth_callback': callback}
        url = self.REQUEST_TOKEN_URL + '?' + urllib.urlencode(args)
        response, content = self._request(url)
        try:
            token = Token.from_string(content)
        except ValueError:
            raise errors.ApiServerError(response, content)
        else:
            self.set_request_token(token)
            return token

    def set_request_token(self, token):
        """ Make the client use the given request token for its calls. """
        self.request_token = token
        self.client = Client(self.consumer, self.request_token)

    def make_authorization_url(self):
        """
        Generate the authorization URL on the Mobile Vikings site.

        You can redirect your user to this page to allow her to grant your
        application access to her data.

        Returns a `str`.
        """
        request = Request.from_consumer_and_token(
            consumer=self.consumer,
            token=self.request_token,
            http_url=self.AUTHORIZE_TOKEN_URL,
        )
        return request.to_url()

    def set_request_verifier(self, verifier):
        """ Set the verifier on the currently active request token. """
        self.request_token.set_verifier(verifier)
        self.client = Client(self.consumer, self.request_token)

    def fetch_access_token(self):
        """
        Fetch an access token.

        Note that you should have already fetched and verified a request token
        before calling this method.

        Returns a :class:`oauth2.Token` instance.
        """
        response, content = self._request(self.ACCESS_TOKEN_URL)
        try:
            token = Token.from_string(content)
        except ValueError:
            raise errors.ApiServerError(response, content)
        else:
            self.set_access_token(token)
            return token

    def fetch_access_token_via_xauth(self, username, password):
        """
        Fetch an access token using the xAuth extension.
        See: https://dev.twitter.com/docs/oauth/xauth for more info.

        Unlike the regular fetch_access_token(), you can call this method
        directly after initializing the client.
        """
        data = {
            'x_auth_mode': 'client_auth',
            'x_auth_username': username,
            'x_auth_password': password,
        }
        response, content = self._request(self.ACCESS_TOKEN_URL,
            method = 'POST',
            body = urllib.urlencode(data),
        )
        try:
            token = Token.from_string(content)
        except ValueError:
            raise errors.ApiServerError(response, content)
        else:
            self.set_access_token(token)
            return token

    def set_access_token(self, token):
        """ Make the client use the given access token for its calls. """
        self.access_token = token
        self.client = Client(self.consumer, self.access_token)

    def call(self, method, path, args=None, body='', headers=None,
             format=None):
        """
        Call the Mobile Vikings API.

        ``method``:  the HTTP method, 'GET' for example.
        ``path``: API method to call. See http://mobilevikings.com/api/2.0/doc/
            for an overview.
        ``args`` (optional): dictionary with parameters that will be used for
            the call.
        ``body`` (optional): body of the request.
        ``headers`` (optional): dictionary with HTTP headers.
        ``format`` (optional): output format of the API.

        Note that this method will only succeed if you have successfully
        requested an access token.

        Returns a (`response`, `content`) tuple.
        """
        assert method.upper() in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD')
        if args is None:
            args = {}
        if format is None:
            format = self.format
        assert format in ('json', 'xml', 'pickle', 'yaml')
        url = self.BASE_URL + path + '.' + format
        if args:
            url += '?' + urllib.urlencode(args)
        return self._request(url, method, body, headers)

    def get(self, path, args=None, body='', headers=None, format=None):
        """ Shortcut for `call()` with 'GET' method. """
        return self.call('GET', path, args, body, headers, format)

    def post(self, path, args=None, body='', headers=None, format=None):
        """ Shortcut for `call()` with 'POST' method. """
        return self.call('POST', path, args, body, headers, format)
