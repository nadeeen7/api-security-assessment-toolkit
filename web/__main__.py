"""Local single-origin server for the web app:  python -m web

Serves both the JSON API and the built React frontend (webui/dist) from one
loopback origin, so the packaged run needs no separate Vite dev server.

Binds loopback only. Threaded so the browser can poll job status while the
single assessment worker runs; job execution is still serialised.
"""
from pathlib import Path

from web.app import create_app

HOST = "127.0.0.1"
PORT = 5055

if __name__ == "__main__":
    application = create_app()
    frontend = Path(application.extensions["frontend_root"])
    base = "http://" + HOST + ":" + str(PORT)
    print("API Security Assessment Toolkit - local server on " + base)
    if (frontend / "index.html").is_file():
        print("Web interface: " + base + "/")
    else:
        print("The web interface has not been built yet. Run:")
        print("  npm --prefix webui ci")
        print("  npm --prefix webui run build")
        print("Then restart `python -m web`. Expected build at " + str(frontend))
    print("Only test systems you own or have explicit authorization to assess.")
    application.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
