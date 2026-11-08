"""Compatibility of the pinned Flask test client with current Werkzeug metadata.

Only the test client's User-Agent version string is supplied. Application request,
response, authentication and security behavior are unchanged.
"""
from importlib.metadata import version
import werkzeug

if not hasattr(werkzeug, '__version__'):
    werkzeug.__version__ = version('werkzeug')
