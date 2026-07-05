from app import create_app
from app import db
from app.db import SessionLocal
from app.models import Server



def build_app(tmp_path):
    return create_app({
        'TESTING': True,
        'DATABASE_URL': f"sqlite:///{tmp_path / 'test.db'}",
        'SECRET_KEY': 'test-secret',
        'APP_ENCRYPTION_KEY': 'test-key-for-unit-tests',
    })



def test_index_page_loads(tmp_path):
    app = build_app(tmp_path)
    try:
        client = app.test_client()
        response = client.get('/')

        assert response.status_code == 200
        assert 'Добавить сервер'.encode('utf-8') in response.data
    finally:
        SessionLocal.remove()
        db.engine.dispose()



def test_healthcheck_returns_ok(tmp_path):
    app = build_app(tmp_path)
    try:
        client = app.test_client()
        response = client.get('/health')

        assert response.status_code == 200
        assert response.json == {'status': 'ok'}
    finally:
        SessionLocal.remove()
        db.engine.dispose()



def test_add_server_stores_encrypted_credentials(tmp_path):
    app = build_app(tmp_path)
    try:
        client = app.test_client()
        response = client.post('/servers', data={
            'name': 'lin',
            'host': '172.16.0.17',
            'port': '22',
            'username': 'root',
            'auth_type': 'password',
            'password': 'pass123',
            'sudo_password': 'sudo123',
        }, follow_redirects=True)

        assert response.status_code == 200

        with app.app_context():
            session = SessionLocal()
            try:
                server = session.query(Server).one()
                assert server.name == 'lin'
                assert server.encrypted_password != 'pass123'
                assert server.encrypted_sudo_password != 'sudo123'
            finally:
                session.close()
    finally:
        SessionLocal.remove()
        db.engine.dispose()
