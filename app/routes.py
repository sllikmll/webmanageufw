from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for

from .crypto import CredentialCipher
from .db import SessionLocal
from .models import Server
from .services.fail2ban import parse_fail2ban_jail_status, parse_fail2ban_status
from .services.ufw import build_add_rule_command, build_delete_rule_command, parse_ufw_status_numbered
from .ssh import RemoteExecutor, SSHCredentials

web = Blueprint('web', __name__)


def _cipher() -> CredentialCipher:
    return CredentialCipher(current_app.config['APP_ENCRYPTION_KEY'])


def _session():
    return SessionLocal()


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


def _fetch_server_state(server: Server) -> dict:
    executor = RemoteExecutor(_server_creds(server))
    ufw = parse_ufw_status_numbered(executor.run('ufw status numbered', use_sudo=True))
    fail2ban = parse_fail2ban_status(executor.run('fail2ban-client status', use_sudo=True))
    jail_details = []
    for jail in fail2ban['jails']:
        jail_details.append(parse_fail2ban_jail_status(executor.run(f'fail2ban-client status {jail}', use_sudo=True)))
    return {'ufw': ufw, 'fail2ban': fail2ban, 'jail_details': jail_details}


@web.get('/health')
def health():
    return jsonify({'status': 'ok'})


@web.get('/')
def index():
    session = _session()
    try:
        servers = session.query(Server).order_by(Server.name.asc()).all()
        return render_template('index.html', servers=servers)
    finally:
        session.close()


@web.post('/servers')
def create_server():
    session = _session()
    cipher = _cipher()
    try:
        auth_type = request.form['auth_type']
        server = Server(
            name=request.form['name'].strip(),
            host=request.form['host'].strip(),
            port=int(request.form.get('port', '22') or '22'),
            username=request.form['username'].strip(),
            auth_type=auth_type,
            encrypted_password=cipher.encrypt(request.form.get('password')) if auth_type == 'password' else None,
            encrypted_private_key=cipher.encrypt(request.form.get('private_key')) if auth_type == 'ssh_key' else None,
            encrypted_sudo_password=cipher.encrypt(request.form.get('sudo_password')),
        )
        session.add(server)
        session.commit()
        flash('Сервер добавлен', 'success')
        return redirect(url_for('web.index'))
    finally:
        session.close()


@web.post('/servers/<int:server_id>/delete')
def delete_server(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        if server:
            session.delete(server)
            session.commit()
            flash('Сервер удалён', 'success')
        return redirect(url_for('web.index'))
    finally:
        session.close()


@web.post('/servers/<int:server_id>/test')
def test_server(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        output = executor.run('hostname && whoami')
        flash(f'Подключение OK: {output.strip()}', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Подключение не удалось: {exc}', 'error')
    finally:
        session.close()
    return redirect(url_for('web.index'))


@web.get('/servers/<int:server_id>')
def server_detail(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        state = _fetch_server_state(server)
        return render_template('server_detail.html', server=server, **state)
    except Exception as exc:  # noqa: BLE001
        flash(f'Не удалось получить состояние сервера: {exc}', 'error')
        return redirect(url_for('web.index'))
    finally:
        session.close()


@web.post('/servers/<int:server_id>/ufw/action')
def ufw_action(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        action = request.form['action']
        command = {'enable': 'ufw --force enable', 'disable': 'ufw disable', 'reload': 'ufw reload'}[action]
        executor.run(command, use_sudo=True)
        flash(f'UFW: {action} выполнено', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'UFW ошибка: {exc}', 'error')
    finally:
        session.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/ufw/rules')
def add_ufw_rule(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
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
        session.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/ufw/rules/delete')
def delete_ufw_rule(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        executor.run(build_delete_rule_command(int(request.form['rule_number'])), use_sudo=True)
        flash('UFW rule удалено', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Не удалось удалить UFW rule: {exc}', 'error')
    finally:
        session.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/fail2ban/ban')
def ban_ip(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        jail = request.form['jail']
        ip = request.form['ip']
        executor.run(f'fail2ban-client set {jail} banip {ip}', use_sudo=True)
        flash('IP забанен', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Fail2ban ban ошибка: {exc}', 'error')
    finally:
        session.close()
    return redirect(url_for('web.server_detail', server_id=server_id))


@web.post('/servers/<int:server_id>/fail2ban/unban')
def unban_ip(server_id: int):
    session = _session()
    try:
        server = session.get(Server, server_id)
        executor = RemoteExecutor(_server_creds(server))
        jail = request.form['jail']
        ip = request.form['ip']
        executor.run(f'fail2ban-client set {jail} unbanip {ip}', use_sudo=True)
        flash('IP разбанен', 'success')
    except Exception as exc:  # noqa: BLE001
        flash(f'Fail2ban unban ошибка: {exc}', 'error')
    finally:
        session.close()
    return redirect(url_for('web.server_detail', server_id=server_id))
