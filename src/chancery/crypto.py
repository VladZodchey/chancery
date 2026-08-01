from nacl import secret, utils
from nacl.pwhash import argon2id

KEY_LENGTH = secret.SecretBox.KEY_SIZE
SALT_LENGTH = argon2id.SALTBYTES


def derive_key(password: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    """Derive a 32-byte symmetric key from a password with Argon2id."""
    return argon2id.kdf(KEY_LENGTH, password.encode("utf-8"), salt, opslimit, memlimit)


def encrypt(plaintext: bytes, password: str, opslimit: int, memlimit: int) -> tuple[bytes, bytes, int, int]:
    """Encrypt plaintext with a key derived from ``password``.

    Returns ``(ciphertext, salt, opslimit, memlimit)``. The ciphertext embeds
    its own random nonce (SecretBox format).
    """
    salt = utils.random(SALT_LENGTH)
    key = derive_key(password, salt, opslimit, memlimit)
    ciphertext = secret.SecretBox(key).encrypt(plaintext)
    return ciphertext, salt, opslimit, memlimit


def decrypt(ciphertext: bytes, password: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    """Decrypt ciphertext previously produced by :func:`encrypt`.

    Raises ``nacl.exceptions.CryptoError`` on any failure (wrong password,
    tampered data).
    """
    key = derive_key(password, salt, opslimit, memlimit)
    return secret.SecretBox(key).decrypt(ciphertext)
