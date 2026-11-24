import dashboard_api

class _FakeSession:

    def __init__(self, return_value):
        self._return_value = return_value

    def execute_read(self, fn, query):
        return fn(self, query)

    def run(self, query):
        return _FakeResult()

class _FakeResult:

    def keys(self):
        return ['n']

    def __iter__(self):
        return iter([{'n': 33}])

def test_query_console_uses_execute_read_not_removed_api(monkeypatch):
    fake_session = _FakeSession(return_value=None)

    class _FakeDriver:

        def session(self):

            class _Ctx:

                def __enter__(self_):
                    return fake_session

                def __exit__(self_, *a):
                    return False
            return _Ctx()
    monkeypatch.setattr(dashboard_api, 'driver', _FakeDriver())
    client = dashboard_api.app.test_client()
    resp = client.post('/api/query', json={'query': 'MATCH (c:Campaign) RETURN count(c) AS n'})
    assert resp.status_code == 200
    assert not hasattr(fake_session, 'read_transaction')