from app.crypto import CredentialCipher


def test_encrypt_and_decrypt_roundtrip():
    cipher = CredentialCipher("test-key-for-unit-tests")

    encrypted = cipher.encrypt("super-secret")

    assert encrypted != "super-secret"
    assert cipher.decrypt(encrypted) == "super-secret"
