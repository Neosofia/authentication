"""RSA public key JWK helpers (RFC 7517 / RFC 7638)."""

import base64
import hashlib
import json
from typing import cast

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def _b64url_uint(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def _rsa_jwk_components(public_key_pem: str) -> tuple[str, str]:
    pub_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(pub_key, RSAPublicKey):
        raise ValueError("key is not RSA")
    pub_numbers = cast(RSAPublicKey, pub_key).public_numbers()
    return _b64url_uint(pub_numbers.n), _b64url_uint(pub_numbers.e)


def compute_kid(public_key_pem: str) -> str:
    """Compute the RFC 7638 JWK Thumbprint for a given RSA public key."""
    n_b64, e_b64 = _rsa_jwk_components(public_key_pem)
    thumbprint_data = json.dumps(
        {"e": e_b64, "kty": "RSA", "n": n_b64},
        separators=(",", ":"),
        sort_keys=True,
    )
    thumbprint_hash = hashlib.sha256(thumbprint_data.encode()).digest()
    return base64.urlsafe_b64encode(thumbprint_hash).rstrip(b"=").decode()


def pem_to_jwk(pem: str) -> dict:
    """Convert a PEM-encoded RSA public key to a JWK dict."""
    n_b64, e_b64 = _rsa_jwk_components(pem)
    kid = compute_kid(pem)
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n_b64, "e": e_b64}
