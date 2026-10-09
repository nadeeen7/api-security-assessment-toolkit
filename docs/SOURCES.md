# Official references consulted

Consulted 2026-10-07. These explain the underlying APIs and manual workflow; they do not certify this toolkit.

- Python virtual environments and Windows activation: https://docs.python.org/3/library/venv.html
- Python Windows installation: https://docs.python.org/3/using/windows.html
- Requests timeout semantics and redirects: https://requests.readthedocs.io/en/latest/user/quickstart/
- Requests HTTPS verification: https://requests.readthedocs.io/en/stable/user/advanced/
- PyJWT verified vs unverified decoding and explicit algorithm policy: https://pyjwt.readthedocs.io/en/stable/api.html
- OpenAPI Spec Validator: https://openapi-spec-validator.readthedocs.io/en/latest/
- Flask local development server: https://flask.palletsprojects.com/en/stable/quickstart/
- Burp Repeater: https://portswigger.net/burp/documentation/desktop/tools/repeater
- Sending and inspecting requests in Repeater: https://portswigger.net/burp/documentation/desktop/tools/repeater/http-messages

Important implementation choices: fixed HS256 validation in the lab, unverified metadata inspection only in the JWT analyzer, no redirects in Requests, loopback-only lab binding and no debug server exposure.
