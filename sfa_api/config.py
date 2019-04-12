import os


import requests


from sfa_api import __version__


class Config(object):
    API_VERSION = __version__
    REDOC_VERSION = 'next'
    AUTH0_BASE_URL = 'https://solarforecastarbiter.auth0.com'
    AUTH0_AUDIENCE = 'https://api.solarforecastarbiter.org'
    JWT_KEY = requests.get(
        AUTH0_BASE_URL + '/.well-known/jwks.json').json()
    MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
    MYSQL_PORT = os.getenv('MYSQL_PORT', '3306')
    MYSQL_USER = os.getenv('MYSQL_USER', None)
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', None)
    MYSQL_DATABASE = os.getenv('MYSQL_DATABASE', None)
    SFA_API_STATIC_DATA = os.getenv('SFA_API_STATIC_DATA', False)


class ProductionConfig(Config):
    DEBUG = False


class DevelopmentConfig(Config):
    DEBUG = True
    MYSQL_USER = 'apiuser'
    MYSQL_PASSWORD = 'thisisaterribleandpublicpassword'
    MYSQL_DATABASE = 'arbiter_data'


class TestingConfig(Config):
    TESTING = True
    MYSQL_USER = 'apiuser'
    MYSQL_PASSWORD = 'thisisaterribleandpublicpassword'
    MYSQL_DATABASE = 'arbiter_data'
