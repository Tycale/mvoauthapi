===============================
Mobile Vikings OAuth API Client
===============================

.. contents::


Overview
========

OAuth is an authorization protocol that allows applications (a balance checker
on your Android phone, for example) to consume user data from a service
provider (the Mobile Vikings API) data without having to know the user's
credentials. The ``mvoauthapi`` package contains a client for the Mobile
Vikings API with OAuth support.


Installation
============

Run the following command in the directory containing this ``README`` file::

    python setup.py install


Calling the Mobile Vikings API
==============================

Registering your application
----------------------------

Before you can call the Mobile Vikings API you should register your
application. Send a request to mailto:info@mobilevikings.com. Don't forget to
include the name of your application, a short description of its functionality
and the username of your Mobile Vikings account. We will send you the consumer
key and secret you need to initialize the API client.

Testing the API
---------------

The ``call.py`` file contains a sample implementation that calls the Mobile
Vikings API using the OAuth client. To request the balance on a SIM card,
for example, execute the following command::

    python call.py sim_balance add_price_plan=1

Visit the `API documentation`_ page for an overview of the available methods
and their arguments.

.. _`API documentation`: http://mobilevikings.com/api/2.0/doc/

If the `xAuth extension`_ has been enabled for your consumer, you can test it by
passing the ``-x`` option to ``call.py``. You will be prompted for an account's
username and password instead of being redirected to the Mobile Vikings site.
Note that xAuth is not enabled by default. If you want to use it, email us at
mailto:info@mobilevikings.com and explain why your application requires it.

.. _`xAuth extension`: https://dev.twitter.com/docs/oauth/xauth

``call.py`` will store your consumer credentials and tokens in
``~/.mvoauthapi.cfg`` so you don't have to re-enter your data and go through
the access token request process each time you make a call.


Using the client in your application
====================================

Acquiring an access token
-------------------------

The OAuth protocol implements authorization by exchanging tokens. First, the
application fetches a request token with a given callback URL. Using this
token, it can redirect the user to an authorization URL on the Mobile Vikings
site. On this page, the user is asked if she wants to grant permission to the
application. If she does, she is redirected to the callback URL that now
contains a verification code. The application can then use the verification
code to request an access token. With this access token, the API calls can
finally be made.

Example
-------

::

    from mvoauthapi.client import ApiClient, Token
    api = ApiClient(consumer_key, consumer_secret)
    api.fetch_request_token(callback='http://my-app.com/access_granted')
    url = api.make_authorization_url()

Now, redirect the user to the authorization URL. If she accepts, she will be
redirected to the ``access_granted`` page of your site. There will be
``oauth_verifier`` and ``oauth_token`` GET query parameters present in the URL.
Pass them to the client and fetch the access token.

::

    request_key = request.GET['oauth_token']
    request_secret = '' # Fetch this from your session or db.
    verifier = request.GET['oauth_verifier']
    request_token = Token(request_key, request_secret)
    request_token.set_verifier(verifier)
    api = ApiClient(consumer_key, consumer_secret)
    api.set_request_token(request_token)
    access_token = api.fetch_access_token()

You can now use the ``api`` object to make calls.

::

    api.get('top_up_history')

Note: if you don't want to use a redirect to your application's site, omit the
``callback`` argument in the ``fetch_request_token`` call. The Mobile Vikings
API will then display the verification code to the user when access has been
granted.

xAuth
-----

Simply call ``fetch_access_token_via_xauth()`` after initializing the
client. It is imperative that you do *not* store the user's credentials. Use
them once to request the access token and discard them afterwards. From then
on, use the access token to make calls.

::

    api = ApiClient(consumer_key, consumer_secret)
    api.fetch_access_token_via_xauth(username, password)
    api.get('sim_balance')


Re-using an existing access token
---------------------------------

Your application can re-use the access token once it has been acquired; you
need not go through the authorization process again. The token will stay valid
until the user revokes it.

::

    api = ApiClient(consumer_key, consumer_secret)
    api.set_access_token(access_token)
    api.get('sim_balance')


Support
=======

If you have questions, comments or suggestions, pay a visit to the `Mobile
Vikings API users group`_.

.. _`Mobile Vikings API users group`: http://groups.google.com/group/mobile-vikings-api-users


.. vim: tw=79
