import json
from http import HTTPMethod, HTTPStatus
from typing import Any, NoReturn

import requests
import rsa

_PEM_FIRST_LINE = "-----BEGIN RSA PUBLIC KEY-----"
_PEM_LAST_LINE = "-----END RSA PUBLIC KEY-----"


def _key_to_str(key: rsa.PublicKey | rsa.PublicKey) -> str:
    return (
        key.save_pkcs1()
        .decode()
        .replace(_PEM_FIRST_LINE, "")
        .replace(_PEM_LAST_LINE, "")
        .replace("\n", "")
    )


def _normalize_dict(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")


class WGNodeAPIException(Exception):
    def __init__(self, http_status_code: HTTPStatus, detail: str):
        self.http_status_code = http_status_code
        self.detail = detail
        super().__init__(f"{self.detail} (HTTP {self.http_status_code})")


class WGNodeClient:
    _base_url: str
    _private_key: rsa.PrivateKey
    _session: requests.Session

    def __init__(self, base_url: str, private_key: rsa.PrivateKey, public_key: rsa.PublicKey):
        self._base_url = base_url.rstrip("/")
        self._private_key = private_key

        self._session = requests.Session()
        self._session.headers.update({"Client-Public-Key": _key_to_str(public_key)})

    def _sign_request_params(
        self,
        path_params: dict[str, Any],
        query_params: dict[str, Any],
        body: dict[str, Any],
    ) -> str:
        """
        Sings provided request params using private key, returns signature in hex.
        """

        path_params_bytes = _normalize_dict(path_params)
        query_params_bytes = _normalize_dict(query_params)
        body_bytes = _normalize_dict(body)

        # bytes to be signed are concatenation of path params, query params and body
        sign_bytes = path_params_bytes + query_params_bytes + body_bytes
        signature = rsa.sign(sign_bytes, self._private_key, "SHA-1")
        return signature.hex()

    def _api_request(
        self,
        method: HTTPMethod,
        api_method: str,
        path_params: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> requests.Response:
        """Sends valid signed API request, returns requests.Response response object."""
        if not path_params:
            path_params = {}
        if not query_params:
            query_params = {}
        if not body:
            body = {}

        signature = self._sign_request_params(path_params, query_params, body)
        return self._session.request(
            method=method,
            url=f"{self._base_url}{api_method}".format(**path_params),
            params=query_params,
            json=body,
            headers={"Request-Params-Signature": signature},
        )

    @staticmethod
    def _parse_response(
        response: requests.Response, plaintext: bool = False
    ) -> str | dict[str, Any] | NoReturn:
        """Parses server response. Handles API errors."""
        if response.status_code != HTTPStatus.OK:
            detail: str | None = None
            try:
                detail = response.json().get("detail")
            except json.JSONDecodeError:
                pass
            raise WGNodeAPIException(response.status_code, detail)

        if plaintext:
            return response.text
        else:
            return response.json()

    def node_status(self) -> dict[str, Any]:
        resp = self._api_request(HTTPMethod.GET, "/node/status")
        return self._parse_response(resp)

    def node_wipe(self) -> dict[str, Any]:
        resp = self._api_request(HTTPMethod.DELETE, "/node/wipe")
        return self._parse_response(resp)

    def client_create(self, client_id: str) -> dict[str, Any]:
        resp = self._api_request(HTTPMethod.POST, "/client", body={"client_id": client_id})
        return self._parse_response(resp)

    def client_get(self, client_id: str) -> dict[str, Any]:
        resp = self._api_request(
            HTTPMethod.GET, "/client/{client_id}", path_params={"client_id": client_id}
        )
        return self._parse_response(resp)

    def client_config(self, client_id: str) -> dict[str, Any]:
        resp = self._api_request(
            HTTPMethod.GET, "/client/{client_id}/config", path_params={"client_id": client_id}
        )
        return self._parse_response(resp, plaintext=True)

    def client_update(self, client_id: str, enabled: bool) -> dict[str, Any]:
        resp = self._api_request(
            HTTPMethod.PUT,
            "/client/{client_id}",
            path_params={"client_id": client_id},
            query_params={"enabled": enabled},
        )
        return self._parse_response(resp)

    def client_delete(self, client_id: str) -> dict[str, Any]:
        resp = self._api_request(
            HTTPMethod.DELETE, "/client/{client_id}", path_params={"client_id": client_id}
        )
        return self._parse_response(resp)
