"""Craton HSM Python client.

Two transports share one API surface:

- ``HsmClient(mode="local")`` — in-process via the pyo3 ``_native`` extension.
  Private keys never leave the host; microsecond call latency. Requires the
  compiled ``_native`` extension module and a local ``craton_hsm.toml`` or
  default config.

- ``HsmClient(mode="remote", base_url=..., token=..., ...)`` — pure-Python
  client hitting the REST gateway (``craton-hsm-rest``). Useful when the HSM
  runs on a different host. Same method surface as local mode.

Choose at construction time — subsequent calls are indistinguishable.

Example::

    from craton_hsm import HsmClient

    # Local
    c = HsmClient(mode="local")
    caps = c.capabilities()
    assert "ML-DSA-65" in caps["ml_dsa_variants"]

    # Remote
    c = HsmClient(mode="remote",
                  base_url="https://hsm.example.com:9443",
                  token="eyJhbG...",              # JWT bearer
                  client_cert=("/etc/tls/cert.pem", "/etc/tls/key.pem"),
                  verify="/etc/tls/ca.pem")
"""
from __future__ import annotations

import base64
from typing import Tuple


class HsmClient:
    """Dual-mode Craton HSM client."""

    def __init__(
        self,
        mode: str = "local",
        *,
        base_url: str | None = None,
        token: str | None = None,
        client_cert: Tuple[str, str] | None = None,
        verify: str | bool = True,
    ):
        if mode not in ("local", "remote"):
            raise ValueError(f"mode must be 'local' or 'remote', got {mode!r}")
        self._mode = mode
        if mode == "local":
            from craton_hsm import _native
            self._backend = _LocalBackend(_native.LocalClient())
        else:
            if base_url is None or token is None:
                raise ValueError("remote mode requires base_url and token")
            self._backend = _RemoteBackend(base_url, token, client_cert, verify)

    @property
    def mode(self) -> str:
        return self._mode

    def capabilities(self) -> dict:
        """Return a capability snapshot (see :func:`service::caps`)."""
        return self._backend.capabilities()

    def sign(self, handle: int, mechanism: str, data: bytes) -> bytes:
        """Sign ``data`` under ``mechanism`` with the private key at ``handle``."""
        return self._backend.sign(handle, mechanism, data)

    def verify(self, handle: int, mechanism: str, data: bytes, signature: bytes) -> bool:
        return self._backend.verify(handle, mechanism, data, signature)

    def encapsulate(self, handle: int, mechanism: str) -> Tuple[bytes, bytes]:
        """Returns ``(ciphertext, shared_secret)``."""
        return self._backend.encapsulate(handle, mechanism)

    def decapsulate(self, handle: int, mechanism: str, ciphertext: bytes) -> bytes:
        return self._backend.decapsulate(handle, mechanism, ciphertext)


# ---------- local (pyo3) backend ----------

class _LocalBackend:
    def __init__(self, native_client):
        self._n = native_client

    def capabilities(self) -> dict:
        return self._n.capabilities().to_dict()

    def sign(self, handle, mechanism, data):
        return self._n.sign(handle, mechanism, data)

    def verify(self, handle, mechanism, data, signature):
        return self._n.verify(handle, mechanism, data, signature)

    def encapsulate(self, handle, mechanism):
        return self._n.encapsulate(handle, mechanism)

    def decapsulate(self, handle, mechanism, ciphertext):
        return self._n.decapsulate(handle, mechanism, ciphertext)


# ---------- remote (REST) backend ----------

class _RemoteBackend:
    """Lightweight REST client speaking craton-hsm-rest. Uses ``requests``.

    Left in pure Python so that users who only want the remote path don't
    need to compile a native extension — they ``pip install`` a universal
    wheel and point it at a daemon.
    """

    def __init__(self, base_url, token, client_cert, verify):
        try:
            import requests  # lazy import
        except ImportError as e:
            raise RuntimeError(
                "remote mode requires the `requests` extra: pip install craton-hsm[remote]"
            ) from e
        self._requests = requests
        self._base = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.cert = client_cert
        self._session.verify = verify

    def _post(self, path, body):
        resp = self._session.post(self._base + path, json=body)
        resp.raise_for_status()
        return resp.json()

    def capabilities(self):
        return self._session.get(self._base + "/v1/capabilities").json()

    def sign(self, handle, mechanism, data):
        body = {"mechanism": mechanism, "data_b64": _b64(data)}
        return _unb64(self._post(f"/v1/keys/{handle}/sign", body)["signature_b64"])

    def verify(self, handle, mechanism, data, signature):
        body = {"mechanism": mechanism, "data_b64": _b64(data), "signature_b64": _b64(signature)}
        return bool(self._post(f"/v1/keys/{handle}/verify", body)["valid"])

    def encapsulate(self, handle, mechanism):
        body = {"mechanism": mechanism}
        r = self._post(f"/v1/kems/{handle}/encapsulate", body)
        return _unb64(r["ciphertext_b64"]), _unb64(r["shared_secret_b64"])

    def decapsulate(self, handle, mechanism, ciphertext):
        body = {"mechanism": mechanism, "ciphertext_b64": _b64(ciphertext)}
        return _unb64(self._post(f"/v1/kems/{handle}/decapsulate", body)["shared_secret_b64"])


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)
