"""Authenticated fixture client; supplies a valid token for legitimate actions.

Negative CSRF checks use the framework's unwrapped client. Application CSRF
protection remains enabled throughout the measured run.
"""
import secrets


def test_client(app):
    client=app.test_client()
    original=client.open
    def open(*args,**kwargs):
        method=kwargs.get('method','GET').upper()
        if 'csrf' in app.extensions and method in ('POST','PUT','PATCH','DELETE'):
            from itsdangerous import URLSafeTimedSerializer
            with client.session_transaction() as session:
                raw=session.setdefault('csrf_token',secrets.token_hex(32))
            headers=dict(kwargs.get('headers') or {})
            headers.setdefault('X-CSRFToken',URLSafeTimedSerializer(app.secret_key,salt='wtf-csrf-token').dumps(raw))
            kwargs['headers']=headers
        return original(*args,**kwargs)
    client.open=open
    return client
