"""Ed25519 signing/verification utilities for Reality Layer V1.

Hardening:
- Strict base64 decoding for signatures.
- Enforce Ed25519 signature length (64 bytes).
- Support loading public keys from PEM bytes/strings.
- Private key file writer sets restrictive permissions (0600) where supported.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ED25519_SIG_LEN: Final[int] = 64


@dataclass(frozen=True)
class KeyPair:
    """A thin wrapper around an Ed25519 keypair (or public key only)."""

    private: Ed25519PrivateKey | None
    public: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        private = Ed25519PrivateKey.generate()
        return cls(private=private, public=private.public_key())

    @classmethod
    def load_private_pem(cls, path: Path, *, password: bytes | None = None) -> "KeyPair":
        private = serialization.load_pem_private_key(path.read_bytes(), password=password)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        return cls(private=private, public=private.public_key())

    @classmethod
    def load_public_pem(cls, path: Path) -> "KeyPair":
        return cls.load_public_pem_bytes(path.read_bytes())

    @classmethod
    def load_public_pem_bytes(cls, pem: bytes) -> "KeyPair":
        public = serialization.load_pem_public_key(pem)
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        return cls(private=None, public=public)

    @classmethod
    def load_public_pem_text(cls, pem_text: str) -> "KeyPair":
        return cls.load_public_pem_bytes(pem_text.encode("utf-8"))

    def write_private_pem(self, path: Path, *, mode: int = 0o600) -> None:
        if not self.private:
            raise ValueError("private key required")
        pem = self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        try:
            os.chmod(path, mode)
        except OSError:
            # Best-effort on platforms that don't support chmod semantics.
            pass

    def write_public_pem(self, path: Path, *, mode: int = 0o644) -> None:
        pem = self.public_pem_bytes()
        path.write_bytes(pem)
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def public_pem_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def key_id(self) -> str:
        return "ueg:sha256:" + hashlib.sha256(self.public_pem_bytes()).hexdigest()

    def legacy_key_id(self) -> str:
        return "ueg:" + hashlib.sha256(self.public_pem_bytes()).hexdigest()[:16]

    def validate_key_id(self, claimed: str, *, allow_legacy: bool) -> None:
        if claimed == self.key_id():
            return
        if allow_legacy and claimed == self.legacy_key_id():
            return
        raise ValueError("key id does not match the public-key fingerprint")

    def sign_b64(self, message: bytes) -> str:
        if not self.private:
            raise ValueError("private key required")
        sig = self.private.sign(message)
        return base64.b64encode(sig).decode("ascii")

    def verify_b64(self, message: bytes, signature_b64: str) -> bool:
        """Return True iff signature is a valid Ed25519 signature over message."""
        try:
            sig = base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError):
            return False
        if len(sig) != _ED25519_SIG_LEN:
            return False
        try:
            self.public.verify(sig, message)
            return True
        except Exception:
            return False
