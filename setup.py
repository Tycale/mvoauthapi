from setuptools import setup, find_packages

import mvoauthapi


params = {
    'name': 'mvoauthapi',
    'version':  mvoauthapi.__version__,
    'url': 'http://github.com/kvsn/mvoauthapi',
    'license': 'BSD',
    'description': 'Mobile Vikings OAuth API Client',
    'long_description': open('README.rst').read(),
    'keywords': 'mobile vikings oauth api client',
    'author': 'Koen Vossen',
    'author_email': 'koen.vossen@citylive.be',
    'packages': find_packages(),
    'install_requires': ['oauth2'],
    'classifiers': [
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Operating System :: OS Independent',
    ],
}

setup(**params)
