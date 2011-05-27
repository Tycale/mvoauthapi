import os
import webbrowser

from optparse import OptionParser
from ConfigParser import ConfigParser

from mvoauthapi import errors
from mvoauthapi.client import ApiClient, Token


CONFIG_FILE = '~/.mv-oauth-client-python.cfg'
FORMAT = 'json'
MAX_TRIES = 2


def create_api_client_from(config_file, refresh=None, format=FORMAT):
    """
    Create an OAuth client for the Mobile Vikings API from a given
    configuration file. If the required options are not available in the
    config, we will prompt the user via the console and update the config.

    ``refresh`` can be either None, 'access_token', or 'request_token'. In the
    former case, we will try to read all tokens from the config first. When set
    to 'access_token', we will reuse the verified request token from the
    config to request a new access token. When set to 'request_token', we will
    perform new requests for both tokens (in this case, the user will have to
    reconfirm the permission for the application).
    """
    assert refresh is None or refresh in ('request_token', 'access_token')

    def get_option(section, option, callback, default=None):
        if config.has_option(section, option) and config.get(section, option):
            return config.get(section, option)
        else:
            value = callback(section, option)
            if not value and default is not None:
                value = default
            config.set(section, option, value)
            return value

    def console_reader(section, option):
        return raw_input('Please enter your %s %s: ' % (section, option))

    def write_config():
        with open(config_file, 'wb') as fh:
            config.write(fh)

    config = ConfigParser()
    if os.path.isfile(config_file):
        config.read(config_file)

    for section in ('consumer', 'request', 'access'):
        if not config.has_section(section):
            config.add_section(section)

    consumer_key = get_option('consumer', 'key', console_reader)
    consumer_secret = get_option('consumer', 'secret', console_reader)
    write_config()

    api = ApiClient(consumer_key, consumer_secret, format)

    if refresh is None and \
       config.has_option('access', 'key') and \
       config.has_option('access', 'secret'):
        access_key = config.get('access', 'key')
        access_secret = config.get('access', 'secret')
        token = Token(access_key, access_secret)
        api.set_access_token(token)
        write_config()
        return api

    if refresh != 'request_token' and \
       config.has_option('request', 'key') and \
       config.has_option('request', 'secret'):
        request_key = config.get('request', 'key')
        request_secret = config.get('request', 'secret')
        token = Token(request_key, request_secret)
        api.set_request_token(token)
    else:
        callback = get_option('request', 'callback', console_reader, default='oob')
        write_config()
        api.fetch_request_token(callback)
        config.set('request', 'key', api.request_token.key)
        config.set('request', 'secret', api.request_token.secret)
        # Requested new token, remove old verifier.
        config.remove_option('request', 'verifier')
        write_config()

    if config.has_option('request', 'verifier'):
        request_verifier = config.get('request', 'verifier')
    else:
        url = api.make_authorization_url()
        webbrowser.open(url)
        request_verifier = console_reader('request', 'verifier')
        config.set('request', 'verifier', request_verifier)
        write_config()

    api.set_request_verifier(request_verifier)
    api.fetch_access_token()

    config.set('access', 'key', api.access_token.key)
    config.set('access', 'secret', api.access_token.secret)
    write_config()

    return api


def call_mv_api(method, params=None, format=FORMAT, http_method=None):
    if params is None:
        params = {}
    if http_method is None:
        http_method = 'GET'

    config_file = os.path.expanduser(CONFIG_FILE)
    refresh = None
    nr_tries = 0

    while nr_tries < MAX_TRIES:
        try:
            api = create_api_client_from(config_file, refresh, format)
            response, content = api.call(http_method, method, params)
        except (errors.InvalidConsumer, errors.AccessDenied) as exc:
            # Consumer credentials are faulty, remove config to start over.
            if os.path.exists(config_file):
                os.remove(config_file)
        except (errors.RequestTokenExpired, errors.AccessTokenExpired) as exc:
            # MV OAuth API converts request tokens to access tokens. Therefore,
            # we cannot reuse the request token to get a new access token.
            # Thus, we have to ask for a new request token in each case.
            refresh = 'request_token'
        else:
            return content
        finally:
            nr_tries += 1

    raise exc


if __name__ == '__main__':
    usage = 'Usage: python %prog [options] <method> [name=value]*'
    description = 'Mobile Vikings OAuth API client.'

    parser = OptionParser(usage=usage, description=description)

    parser.add_option('-f', '--format',
        default='json',
        help='Output format of the API.',
    )

    parser.add_option('-m', '--http-method',
        default='GET',
        help='HTTP method.',
    )

    options, args = parser.parse_args()
    params = {}

    if not args:
        parser.error('Please specify an API method to call.')

    method = args.pop(0)

    for a in args:
        if '=' in a:
            name, value = a.split('=', 1)
        else:
            name, value = a, ''
        params[name] = value

    print call_mv_api(method, params, options.format, options.http_method)
