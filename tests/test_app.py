from app import create_app
from app import db
from app.db import SessionLocal
from app.models import Server
from app.crypto import CredentialCipher



def build_app(tmp_path):
    return create_app({
        'TESTING': True,
        'DATABASE_URL': f"sqlite:///{tmp_path / 'test.db'}",
        'SECRET_KEY': 'test-secret',
        'APP_ENCRYPTION_KEY': 'test-key-for-unit-tests',
    })



def build_auth_app(tmp_path):
    return create_app({
        'TESTING': True,
        'DATABASE_URL': f"sqlite:///{tmp_path / 'auth.db'}",
        'SECRET_KEY': 'test-secret',
        'APP_ENCRYPTION_KEY': 'test-key-for-unit-tests',
        'ADMIN_USERNAME': 'admin',
        'ADMIN_PASSWORD': 'adminpass',
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



def test_login_required_redirects_to_login_page(tmp_path):
    app = build_auth_app(tmp_path)
    try:
        client = app.test_client()
        response = client.get('/', follow_redirects=False)

        assert response.status_code == 302
        assert '/login' in response.headers['Location']
    finally:
        SessionLocal.remove()
        db.engine.dispose()



def test_login_allows_access_with_valid_credentials(tmp_path):
    app = build_auth_app(tmp_path)
    try:
        client = app.test_client()
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'adminpass',
        }, follow_redirects=True)

        assert response.status_code == 200
        assert 'Добавить сервер'.encode('utf-8') in response.data
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



def test_update_server_changes_fields_and_credentials(tmp_path):
    app = build_app(tmp_path)
    try:
        cipher = CredentialCipher('test-key-for-unit-tests')
        with app.app_context():
            session = SessionLocal()
            try:
                server = Server(
                    name='old-name',
                    host='10.0.0.1',
                    port=22,
                    username='root',
                    auth_type='password',
                    encrypted_password=cipher.encrypt('old-pass'),
                    encrypted_sudo_password=cipher.encrypt('old-sudo'),
                )
                session.add(server)
                session.commit()
                server_id = server.id
            finally:
                session.close()

        client = app.test_client()
        response = client.post(f'/servers/{server_id}/update', data={
            'name': 'new-name',
            'host': '10.0.0.2',
            'port': '2222',
            'username': 'admin',
            'auth_type': 'password',
            'password': 'new-pass',
            'sudo_password': 'new-sudo',
        }, follow_redirects=True)

        assert response.status_code == 200

        with app.app_context():
            session = SessionLocal()
            try:
                server = session.get(Server, server_id)
                assert server.name == 'new-name'
                assert server.host == '10.0.0.2'
                assert server.port == 2222
                assert server.username == 'admin'
                assert cipher.decrypt(server.encrypted_password) == 'new-pass'
                assert cipher.decrypt(server.encrypted_sudo_password) == 'new-sudo'
            finally:
                session.close()
    finally:
        SessionLocal.remove()
        db.engine.dispose()



def test_server_detail_shows_install_actions_when_packages_missing(tmp_path, monkeypatch):
    app = build_app(tmp_path)
    try:
        with app.app_context():
            session = SessionLocal()
            try:
                server = Server(
                    name='lin',
                    host='172.16.0.17',
                    port=22,
                    username='root',
                    auth_type='password',
                )
                session.add(server)
                session.commit()
                server_id = server.id
            finally:
                session.close()

        def fake_fetch(_server):
            return {
                'ufw': {'status': 'not-installed', 'rules': [], 'installed': False, 'raw': ''},
                'fail2ban': {'jails': [], 'installed': False, 'raw': ''},
                'jail_details': [],
            }

        monkeypatch.setattr('app.routes._fetch_server_state', fake_fetch)

        client = app.test_client()
        response = client.get(f'/servers/{server_id}')

        assert response.status_code == 200
        assert 'Установить UFW'.encode('utf-8') in response.data
        assert 'Установить fail2ban'.encode('utf-8') in response.data
    finally:
        SessionLocal.remove()
        db.engine.dispose()
