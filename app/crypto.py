import base64
import hashlib

from cryptography.fernet import Fernet


class CredentialCipher:
    def __init__(self, secret: str):
        digest = hashlib.sha256(secret.encode('utf-8')).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        return self.fernet.encrypt(value.encode('utf-8')).decode('utf-8')

    def decrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        return self.fernet.decrypt(value.encode('utf-8')).decode('utf-8')
