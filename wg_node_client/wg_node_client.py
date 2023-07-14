import json
from http import HTTPMethod, HTTPStatus
from typing import Any, NoReturn

import aiohttp
import rsa

_PEM_FIRST_LINE = "-----BEGIN RSA PUBLIC KEY-----"
_PEM_LAST_LINE = "-----END RSA PUBLIC KEY-----"
_SIGNED_PARTS_SEPARATOR = b";"


def _rsa_key_to_str(key: rsa.PublicKey | rsa.PublicKey) -> str:
    """Converts rsa.PublicKey and rsa.PrivateKey to string."""
    return (
        key.save_pkcs1()
        .decode()
        .replace(_PEM_FIRST_LINE, "")
        .replace(_PEM_LAST_LINE, "")
        .replace("\n", "")
    )


def _normalize(obj: dict[Any, Any]) -> bytes:
    """
    Normalizes dict object to json bytes according to the wg-node requirements.
    >>> _normalize({"foo": "bar", "x": "y"})
    >>> b'{"foo":"bar","x":"y"}'
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


class WGNodeClientException(Exception):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        self.message = (
            f"wg-node API exception: {self.detail} (HTTP status code: {self.status_code})"
        )
        super(WGNodeClientException).__init__()


class WGNodeClient:
    _socket: str
    _session: aiohttp.ClientSession
    _private_key: rsa.PrivateKey
    _https: bool

    def __init__(
        self,
        socket: str,
        *,
        public_key: rsa.PublicKey,
        private_key: rsa.PrivateKey,
        https: bool = False,
    ):
        self._socket = socket
        self._session = aiohttp.ClientSession(
            headers={"API-User-Public-Key": _rsa_key_to_str(public_key)}
        )
        self._private_key = private_key
        self._https = https

    def _sign_request(
        self,
        method: HTTPMethod,
        path_params: dict[str, Any] | None,
        query_params: dict[str, Any] | None,
        body: dict[str, Any] | None,
    ):
        """Signs request according to the wg-node requirements."""
        hostname = self._socket.split(":", 1)[
            0
        ]  # port number is not included in request signature, only hostname

        method_bytes = method.encode()
        hostname_bytes = hostname.encode()
        path_params_bytes = _normalize(path_params) if path_params else b"{}"
        query_params_bytes = _normalize(query_params) if query_params else b"{}"
        body_bytes = _normalize(body) if body else b"{}"
        signed_bytes = (
            method_bytes
            + _SIGNED_PARTS_SEPARATOR
            + hostname_bytes
            + _SIGNED_PARTS_SEPARATOR
            + path_params_bytes
            + _SIGNED_PARTS_SEPARATOR
            + query_params_bytes
            + _SIGNED_PARTS_SEPARATOR
            + body_bytes
        )
        signature = rsa.sign(signed_bytes, self._private_key, "SHA-256")  # todo: was SHA-1
        return signature.hex()

    async def _send_request(
        self,
        method: HTTPMethod,
        path: str,
        *,
        path_params: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        plaintext_response: bool = False,
    ) -> dict[str, Any] | str | NoReturn:
        """Sends request to wg-node API."""
        path = path.format(**path_params) if path_params else path
        url = f"{'https' if self._https else 'http'}://{self._socket}{path}"

        signature = self._sign_request(method, path_params, query_params, body)
        headers = self._session.headers.copy()
        headers.update({"Request-Signature": signature})

        async with self._session.request(
            method, url, params=query_params, json=body, headers=headers
        ) as response:
            if response.status == HTTPStatus.OK:
                if plaintext_response:
                    return await response.text()
                else:
                    return await response.json()
            else:
                detail: str
                try:
                    detail = (await response.json())["detail"]
                except (json.JSONDecodeError, KeyError):
                    detail = await response.text()
                raise WGNodeClientException(response.status, detail)

    # methods related to API users:
    async def api_user_create(self, public_key: str) -> dict[str, Any]:
        """Creates API user."""
        return await self._send_request(
            HTTPMethod.POST, "/api-user/", body={"public_key": public_key}
        )

    async def api_user_delete(self, public_key: str) -> dict[str, Any]:
        """Deletes API user."""
        return await self._send_request(
            HTTPMethod.DELETE, f"/api-user/{public_key}", path_params={"public_key": public_key}
        )

    # methods related to node:
    async def node_status(self) -> dict[str, Any]:
        """Returns information about node."""
        return await self._send_request(HTTPMethod.GET, "/node/status")

    async def node_wipe(self) -> dict[str, Any]:
        """Removes all peers from node."""
        return await self._send_request(HTTPMethod.DELETE, "/node/wipe")

    # methods related to peers:
    async def peer_create(self, peer_id: str) -> dict[str, Any]:
        """Creates new peer."""
        return await self._send_request(HTTPMethod.POST, "/peer/", body={"peer_id": peer_id})

    async def peer_get(self, peer_id: str) -> dict[str, Any]:
        """Returns information about peer."""
        return await self._send_request(
            HTTPMethod.GET, "/peer/{peer_id}", path_params={"peer_id": peer_id}
        )

    async def peer_config(self, peer_id: str) -> str:
        """Returns peer config."""
        return await self._send_request(
            HTTPMethod.GET,
            "/peer/{peer_id}/config",
            path_params={"peer_id": peer_id},
            plaintext_response=True,
        )

    async def peer_update(self, peer_id: str, enabled: bool) -> dict[str, Any]:
        """Enables or disables peer."""
        return await self._send_request(
            HTTPMethod.PUT,
            "/peer/{peer_id}",
            path_params={"peer_id": peer_id},
            body={"enabled": enabled},
        )

    async def peer_delete(self, peer_id: str) -> dict[str, Any]:
        """Permanently deletes peer."""
        return await self._send_request(
            HTTPMethod.DELETE, "/peer/{peer_id}", path_params={"peer_id": peer_id}
        )
