from functools import wraps
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for

from .crypto import CredentialCipher
from .db import SessionLocal
from .models import Server
from .services.fail2ban import parse_fail2ban_jail_status, parse_fail2ban_status
from .services.ufw import build_add_rule_command, build_delete_rule_command, parse_ufw_status_numbered
from .ssh import RemoteExecutor, SSHCredentials

web = Blueprint('web', __name__)

PACKAGE_COMMANDS = {
    'ufw': 'ufw',
    'fail2ban': 'fail2ban-client',
}

PACKAGE_INSTALL_COMMANDS = {
    'ufw': 'export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y ufw',
    'fail2ban': "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y fail2ban && (systemctl enable --now fail2ban || service fail2ban start)",
}



def _cipher() -> CredentialCipher:
    return CredentialCipher(current_app.config['APP_ENCRYPTION_KEY'])



def _session():
    return SessionLocal()



def _auth_enabled() -> bool:
    return bool(current_app.config.get('ADMIN_USERNAME') and current_app.config.get('ADMIN_PASSWORD'))



def _is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    parts = urlparse(target)
    return not parts.netloc and parts.path.startswith('/')



@web.before_app_request
def require_login():
    if not _auth_enabled():
        return None

    endpoint = request.endpoint or ''
    allowed_endpoints = {
        'web.login',
        'web.health',
        'static',
    }
    if endpoint in allowed_endpoints:
        return None

    if session.get('authenticated'):
        return None

    return redirect(url_for('web.login', next=request.full_path if request.query_string else request.path))



def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if _auth_enabled() and not session.get('authenticated'):
            return redirect(url_for('web.login', next=request.path))
        return view_func(*args, **kwargs)

    return wrapper



def _server_creds(server: Server) -> SSHCredentials:
    cipher = _cipher()
    return SSHCredentials(
        host=server.host,
        port=server.port,
        username=server.username,
        password=cipher.decrypt(server.encrypted_password),
        private_key=cipher.decrypt(server.encrypted_private_key),
        sudo_password=cipher.decrypt(server.encrypted_sudo_password),
    )



def _package_installed(executor: RemoteExecutor, package_name: str) -> bool:
    command = PACKAGE_COMMANDS[package_name]
    try:
        executor.run(f'command -v {command}')
        return True
    except Exception:  # noqa: BLE001
        return False



def _ensure_package_installed(executor: RemoteExecutor, package_name: str):
    if not _package_installed(executor, package_name):
        raise RuntimeError(f'{package_name} не установлен на удалённом сервере')



def _fetch_server_state(server: Server) -> dict:
    executor = RemoteExecutor(_server_creds(server))

    ufw_installed = _package_installed(executor, 'ufw')
    if ufw_installed:
        ufw = parse_ufw_status_numbered(executor.run('ufw status numbered', use_sudo=True))
        ufw['installed'] = True
    else:
        ufw = {
            'status': 'not-installed',
            'rules': [],
            'installed': False,
            'raw': '',
        }

    fail2ban_installed = _package_installed(executor, 'fail2ban')
    jail_details = []
    if fail2ban_installed:
        fail2ban = parse_fail2ban_status(executor.run('fail2ban-client status', use_sudo=True))
        fail2ban['installed'] = True
        for jail in fail2ban['jails']:
            jail_details.append(parse_fail2ban_jail_status(executor.run(f'fail2ban-client status {jail}', use_sudo=True)))
    else:
        fail2ban = {
            'jails': [],
            'installed': False,
            'raw': '',
        }

    return {'ufw': ufw, 'fail2ban': fail2ban, 'jail_details': jail_details}



def _apply_server_form(server: Server, form):
    cipher = _cipher()
    auth_type = form['auth_type']

    server.name = form['name'].strip()
    server.host = form['host'].strip()
    server.port = int(form.get('port', '22') or '22')
    server.username = form['username'].strip()
    server.auth_type = auth_type

    password = (form.get('password') or '').strip()
    private_key = (form.get('private_key') or '').strip()
    sudo_password = (form.get('sudo_password') or '').strip()

    if auth_type == 'password':
        if password:
            server.encrypted_password = cipher.encrypt(password)
        elif server.auth_type != 'password':
            server.encrypted_password = None
        server.encrypted_private_key = None
    else:
        if private_key:
            server.encrypted_private_key = cipher.encrypt(private_key)
        elif server.auth_type != 'ssh_key':
            server.encrypted_private_key = None
        server.encrypted_password = None

    if sudo_password:
        server.encrypted_sudo_password = cipher.encrypt(sudo_password)



@web.get('/health')
def health():
    return jsonify({'status': 'ok'})


@web.route('/login', methods=['GET', 'POST'])
def login():
    if not _auth_enabled():
        return redirect(url_for('web.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username == current_app.config['ADMIN_USERNAME'] and password == current_app.config['ADMIN_PASSWORD']:
            session['authenticated'] = True
            flash('Вход выполнен', 'success')
            next_url = request.args.get('next') or request.form.get('next')
            return redirect(next_url if _is_safe_next_url(next_url) else url_for('web.index'))
        flash('Неверный логин или пароль', 'error')

    return render_template('login.html')


@web.post('/logout')
@login_required
def logout():
    session.clear()
    flash('Вы вышли из приложения', 'success')
    return redirect(url_for('web.login'))


@web.get('/')
@login_required
def index():
    session_db = _session()
    try:
        servers = session_db.query(Server).order_by(Server.name.asc()).all()
        return render_template('index.html', servers=servers, auth_enabled=_auth_enabled())
    finally:
        session_db.close()


@web.post('/servers')
@login_required
def create_server():
    session_db = _session()
    try:
        server = Server()
        _apply_server_form(server, request.form)
        session_db.add(server)
        session_db.commit()
        flash('Сервер добавлен', 'success')
        return redirect(url_for('web.index'))
    finally:
        session_db.close()


@web.get('/servers/<int:server_id>/edit')
@login_required
def edit_server(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        return render_template('edit_server.html', server=server)
    finally:
        session_db.close()


@web.post('/servers/<int:server_id>/update')
@login_required
def update_server(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        previous_auth_type = server.auth_type
        _apply_server_form(server, request.form)
        if request.form['auth_type'] == 'password' and not (request.form.get('password') or '').strip() and previous_auth_type != 'password':
            server.encrypted_password = None
        if request.form['auth_type'] == 'ssh_key' and not (request.form.get('private_key') or '').strip() and previous_auth_type != 'ssh_key':
            server.encrypted_private_key = None
        session_db.commit()
        flash('Карточка сервера обновлена', 'success')
        return redirect(url_for('web.server_detail', server_id=server_id))
    finally:
        session_db.close()


@web.post('/servers/<int:server_id>/delete')
@login_required
def delete_server(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        if server:
            session_db.delete(server)
            session_db.commit()
            flash('Сервер удалён', 'success')
        return redirect(url_for('web.index'))
    finally:
        session_db.close()


@web.post('/servers/<int:server_id>/test')
@login_required
def test_server(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        output = executor.run('hostname && whoami')
        flash(f'Подключение OK: {output.strip()}', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Подключение не удалось: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.index'))


@web.get('/servers/<int:server_id>')
@login_required
def server_detail(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        state = _fetch_server_state(server)
        return render_template('server_detail.html', server=server, **state)
    except Exception as exc:  # noqa: BLE001
        flash(f'Не удалось получить состояние сервера: {exc}', 'error')
        return redirect(url_for('web.index'))
    finally:
        session_db.close()


@web.post('/servers/<int:server_id>/packages/install')
@login_required
def install_package(server_id: int):
    package_name = request.form['package_name']
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        executor.run(PACKAGE_INSTALL_COMMANDS[package_name], use_sudo=True)
        flash(f'{package_name} установлен', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Не удалось установить {package_name}: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/ufw/action')
@login_required
def ufw_action(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        _ensure_package_installed(executor, 'ufw')
        action = request.form['action']
        command = {'enable': 'ufw --force enable', 'disable': 'ufw disable', 'reload': 'ufw reload'}[action]
        executor.run(command, use_sudo=True)
        flash(f'UFW: {action} выполнено', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'UFW ошибка: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/ufw/rules')
@login_required
def add_ufw_rule(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        _ensure_package_installed(executor, 'ufw')
        command = build_add_rule_command(
            action=request.form['action'],
            port=request.form['port'],
            protocol=request.form.get('protocol', 'tcp'),
            source=request.form.get('source') or None,
            comment=request.form.get('comment') or None,
        )
        executor.run(command, use_sudo=True)
        flash('UFW rule добавлено', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Не удалось добавить UFW rule: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/ufw/rules/delete')
@login_required
def delete_ufw_rule(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        _ensure_package_installed(executor, 'ufw')
        executor.run(build_delete_rule_command(int(request.form['rule_number'])), use_sudo=True)
        flash('UFW rule удалено', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Не удалось удалить UFW rule: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/fail2ban/ban')
@login_required
def ban_ip(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        _ensure_package_installed(executor, 'fail2ban')
        jail = request.form['jail']
        ip = request.form['ip']
        executor.run(f'fail2ban-client set {jail} banip {ip}', use_sudo=True)
        flash('IP забанен', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Fail2ban ban ошибка: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/fail2ban/unban')
@login_required
def unban_ip(server_id: int):
    session_db = _session()
    try:
        server = session_db.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        _ensure_package_installed(executor, 'fail2ban')
        jail = request.form['jail']
        ip = request.form['ip']
        executor.run(f'fail2ban-client set {jail} unbanip {ip}', use_sudo=True)
        flash('IP разбанен', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Fail2ban unban ошибка: {exc}', 'error')
    finally:
        session_db.close()
    return redirect(url_for('web.server_detail', server_id=server_id))
