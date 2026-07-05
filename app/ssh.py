import io
from dataclasses import dataclass

import paramiko


@dataclass
class SSHCredentials:
    host: str
    port: int
    username: str
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None


class RemoteExecutor:
    def __init__(self, creds: SSHCredentials):
        self.creds = creds
        self._client = None

    def _load_private_key(self, private_key: str):
        key_buffer = io.StringIO(private_key)
        for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            key_buffer.seek(0)
            try:
                return key_cls.from_private_key(key_buffer)
            except paramiko.SSHException:
                continue
        raise RuntimeError('Не удалось распарсить SSH key')

    def _connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            'hostname': self.creds.host,
            'port': self.creds.port,
            'username': self.creds.username,
            'timeout': 15,
            'look_for_keys': False,
            'allow_agent': False,
        }
        if self.creds.private_key:
            kwargs['pkey'] = self._load_private_key(self.creds.private_key)
        else:
            kwargs['password'] = self.creds.password
        client.connect(**kwargs)
        return client

    def __enter__(self):
        if self._client is None:
            self._client = self._connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def run(self, command: str, use_sudo: bool = False) -> str:
        persistent_client = self._client is not None
        client = self._client or self._connect()
        try:
            if use_sudo and self.creds.username != 'root':
                sudo_password = self.creds.sudo_password or self.creds.password
                if not sudo_password:
                    raise RuntimeError('Для sudo-команд нужен sudo password')
                command = f"sudo -S -p '' bash -lc {command!r}"
                stdin, stdout, stderr = client.exec_command(command)
                stdin.write(sudo_password + "\n")
                stdin.flush()
            else:
                stdin, stdout, stderr = client.exec_command(f"bash -lc {command!r}")
            out = stdout.read().decode('utf-8', 'ignore')
            err = stderr.read().decode('utf-8', 'ignore')
            code = stdout.channel.recv_exit_status()
            if code != 0:
                raise RuntimeError(err.strip() or out.strip() or f'Команда завершилась с кодом {code}')
            return out
        finally:
            if not persistent_client:
                client.close()

    def run_script(self, script: str, use_sudo: bool = False) -> str:
        persistent_client = self._client is not None
        client = self._client or self._connect()
        try:
            if use_sudo and self.creds.username != 'root':
                sudo_password = self.creds.sudo_password or self.creds.password
                if not sudo_password:
                    raise RuntimeError('Для sudo-команд нужен sudo password')
                stdin, stdout, stderr = client.exec_command("sudo -S -p '' bash -s")
                stdin.write(sudo_password + "\n")
                stdin.write(script)
                if not script.endswith("\n"):
                    stdin.write("\n")
                stdin.flush()
            else:
                stdin, stdout, stderr = client.exec_command("bash -s")
                stdin.write(script)
                if not script.endswith("\n"):
                    stdin.write("\n")
                stdin.flush()
            out = stdout.read().decode('utf-8', 'ignore')
            err = stderr.read().decode('utf-8', 'ignore')
            code = stdout.channel.recv_exit_status()
            if code != 0:
                raise RuntimeError(err.strip() or out.strip() or f'Команда завершилась с кодом {code}')
            return out
        finally:
            if not persistent_client:
                client.close()
