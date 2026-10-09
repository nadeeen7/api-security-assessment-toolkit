import threading
from urllib.parse import urlsplit
import pytest
import requests
from werkzeug.serving import make_server
from lab.app import create_app
from core.http_client import HTTPClient

@pytest.fixture(autouse=True)
def block_external_network(monkeypatch):
    original = requests.Session.send
    def guarded(self, request, **kwargs):
        assert urlsplit(request.url).hostname == "127.0.0.1", "Tests must stay local"
        return original(self, request, **kwargs)
    monkeypatch.setattr(requests.Session, "send", guarded)

@pytest.fixture
def lab():
    app = create_app()
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield app, "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()

@pytest.fixture
def client(lab):
    client = HTTPClient(lab[1], allow_post=True)
    yield client
    client.close()

@pytest.fixture
def identities(lab):
    app, _ = lab
    with app.test_client() as test:
        return {name: {"Authorization": "Bearer " + test.post("/api/login", json={"username":name, "password":name+"-lab-only"}).json["token"]} for name in ("alice", "bob")}
