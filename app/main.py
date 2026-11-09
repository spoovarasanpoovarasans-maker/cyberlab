"""ASGI entry point: ``uvicorn app.main:app``.

The factory lives in :mod:`app.factory` so importing the app for tests or tooling
does not create a database or touch the data directory.
"""

from .factory import create_app

app = create_app()
