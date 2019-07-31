import pdb
"""
Verify JSON Web Tokens from the configured Auth0 application.
We use a custom solution here instead of a library like
flask-jwt-extended because we only need to verify valid tokens
and not issue any. We use python-jose instead of pyjwt because
it is better documented and is not missing any JWT features.
"""
from functools import wraps
import requests


from flask import (request, Response, current_app, render_template,
                   _request_ctx_stack)
from jose import jwt, jwk
from werkzeug.local import LocalProxy


current_user = LocalProxy(
    lambda: getattr(_request_ctx_stack.top, 'user', ''))
current_jwt_claims = LocalProxy(
    lambda: getattr(_request_ctx_stack.top, 'jwt_claims', None))
current_access_token = LocalProxy(
    lambda: getattr(_request_ctx_stack.top, 'access_token', ''))


def verify_access_token():
    auth = request.headers.get('Authorization', '').split(' ')
    try:
        assert auth[0] == 'Bearer'
        token = jwt.decode(
            auth[1],
            key=current_app.config['JWT_KEY'],
            audience=current_app.config['AUTH0_AUDIENCE'],
            issuer=current_app.config['AUTH0_BASE_URL'] + '/')
    except (jwt.JWTError,
            jwk.JWKError,
            jwt.ExpiredSignatureError,
            jwt.JWTClaimsError,
            AttributeError,
            AssertionError,
            IndexError):
        return False
    else:
        # add the token and sub to the request context stack
        # so they can be accessed elsewhere in the code for
        # proper authorization
        _request_ctx_stack.top.jwt_claims = token
        _request_ctx_stack.top.access_token = auth[1]
        _request_ctx_stack.top.user = token['sub']
        create_user()
        return True


def request_user_info():
    info_request = requests.get(
        current_app.config['AUTH0_BASE_URL'] + '/userinfo',
        headers={
            'Authorization': f'Bearer {current_access_token}',
        })
    user_info = info_request.json()
    return user_info


def create_user():
    """Stores a user in the database.

    Raises BadAPIRequest
        If the users email is not verified.
    """
    info = request_user_info()
    if not info['email_verified']:
        raise BadAPIRequest(user='Unverified user.')
    # store in db here
    # TODO: fix flow of imports, move this somewhere else
    from sfa_api.utils.storage import get_storage
    storage = get_storage()
    storage.store_user(info)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if verify_access_token():
            return f(*args, **kwargs)
        else:
            return Response(
                render_template('auth_error.html'),
                401,
                {'WWW-Authenticate': 'Bearer'})
    return decorated
