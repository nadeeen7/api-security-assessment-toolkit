"""Flask REST API in front of the existing assessment engine.

This package contains NO assessment logic. It validates input, runs main.run()
in a background worker and serves the artifacts the engine already produces.

Import the app factory explicitly:  from web.app import create_app
"""
