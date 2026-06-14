#!/usr/bin/python
"""Deploy a FritzBox PEM certificate bundle to FRITZ!OS."""

from __future__ import annotations

import hashlib
import re
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.client import HTTPResponse

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-not-found,import-untyped]
from ansible.module_utils.ca_file import read_file, sanitize_error  # type: ignore[import-not-found,import-untyped]

CRYPTOGRAPHY_IMPORT_ERROR: Exception | None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception as exc:  # pragma: no cover - handled at runtime by Ansible
    CRYPTOGRAPHY_IMPORT_ERROR = exc
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None

PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |ENCRYPTED |)PRIVATE KEY-----.*?"
    rb"-----END (?:RSA |ENCRYPTED |)PRIVATE KEY-----",
    re.DOTALL,
)
CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
ZERO_SID = "0000000000000000"
SUCCESS_MARKERS = (
    "SSL-Zertifikat wurde erfolgreich importiert",
    "SSL certificate was successful",
    "certificado SSL se ha importado",
    "certificat SSL a été importé",
    "certificato SSL è stato importato",
    "certyfikatu SSL",
)


def _challenge_response(challenge: str, password: str) -> str:
    """Return a FRITZ!OS login response for legacy and PBKDF2 challenges."""
    if challenge.startswith("2$"):
        parts = challenge.split("$")
        if len(parts) != 5 or parts[0] != "2":
            raise RuntimeError("FRITZ!Box returned an unsupported PBKDF2 challenge")
        first_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-16le"),
            bytes.fromhex(parts[2]),
            int(parts[1]),
        )
        second_hash = hashlib.pbkdf2_hmac(
            "sha256",
            first_hash,
            bytes.fromhex(parts[4]),
            int(parts[3]),
        )
        return f"{challenge}${second_hash.hex()}"

    digest_input = f"{challenge}-{password}".encode("utf-16le")
    response_hash = hashlib.md5(digest_input).hexdigest()  # noqa: S324
    return f"{challenge}-{response_hash}"


def _base_url(value: str) -> str:
    """Return a normalized FRITZ!Box base URL."""
    url = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be an absolute http or https URL")
    return url


def _https_endpoint(base_url: str) -> tuple[str, int]:
    """Return the HTTPS endpoint for the FRITZ!Box certificate comparison."""
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "https":
        raise ValueError("FritzBox deployment idempotence requires an https base_url")
    return parsed.hostname or "", parsed.port or 443


def _url(base_url: str, path: str, query: dict[str, str] | None = None) -> str:
    """Build an absolute URL below the FRITZ!Box base URL."""
    parsed = urllib.parse.urlsplit(base_url)
    encoded_query = urllib.parse.urlencode(query or {})
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, path, encoded_query, "")
    )


def _decode_response(response: HTTPResponse, data: bytes) -> str:
    """Decode an HTTP response body for XML and message checks."""
    encoding = response.headers.get_content_charset() or "utf-8"
    return data.decode(encoding, errors="replace")


def _ssl_context(validate_certs: bool) -> ssl.SSLContext:
    """Return an SSL context matching the certificate validation setting."""
    if validate_certs:
        return ssl.create_default_context()
    return ssl._create_unverified_context()  # noqa: S323


class FritzBoxClient:
    """Small FRITZ!OS HTTP client for certificate import."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        timeout: int,
        validate_certs: bool,
    ) -> None:
        """Initialize the client connection settings."""
        self.base_url = _base_url(base_url)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.context = _ssl_context(validate_certs)
        self.sid = ""

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        """Execute one FRITZ!OS HTTP request and return decoded text."""
        url = _url(self.base_url, path, query)
        request = urllib.request.Request(
            url,
            data=data,
            headers=headers or {},
            method=method,
        )
        try:
            if urllib.parse.urlsplit(url).scheme == "https":
                response_context = urllib.request.urlopen(  # noqa: S310
                    request,
                    timeout=self.timeout,
                    context=self.context,
                )
            else:
                response_context = urllib.request.urlopen(  # noqa: S310
                    request,
                    timeout=self.timeout,
                )
            with response_context as response:
                body = response.read()
                return _decode_response(response, body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"FRITZ!Box request failed with HTTP {exc.code}: {body[:400]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"FRITZ!Box request failed: {exc.reason}") from exc

    @staticmethod
    def _xml_text(xml_text: str, element: str) -> str:
        """Read one element text value from a FRITZ!OS XML response."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise RuntimeError("FRITZ!Box returned invalid XML") from exc
        value = root.findtext(f".//{element}") or ""
        return value.strip()

    def login(self) -> str:
        """Log in and return a valid FRITZ!OS SID."""
        login_xml = self._request("GET", "/login_sid.lua")
        challenge = self._xml_text(login_xml, "Challenge")
        if not challenge:
            raise RuntimeError("FRITZ!Box did not return a login challenge")

        auth_xml = self._request(
            "GET",
            "/login_sid.lua",
            query={
                "username": self.username,
                "response": _challenge_response(challenge, self.password),
            },
        )
        sid = self._xml_text(auth_xml, "SID")
        if not sid or sid == ZERO_SID:
            raise RuntimeError("FRITZ!Box login failed")
        self.sid = sid
        return sid

    def logout(self) -> None:
        """Log out and ignore logout transport errors."""
        if not self.sid or self.sid == ZERO_SID:
            return
        try:
            self._request(
                "GET",
                "/login_sid.lua",
                query={"logout": "1", "sid": self.sid},
            )
        except RuntimeError:
            pass

    def import_certificate(self, bundle: bytes) -> None:
        """Upload a certificate bundle and require a successful response."""
        sid = self.sid or self.login()
        boundary = f"ansible-ca-{secrets.token_hex(16)}"
        body = _multipart_body(boundary, sid, bundle)
        response = self._request(
            "POST",
            "/cgi-bin/firmwarecfg",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        if not _import_succeeded(response):
            raise RuntimeError("FRITZ!Box did not confirm certificate import")

    def current_certificate(self) -> x509.Certificate:
        """Return the certificate currently served by the FRITZ!Box HTTPS port."""
        host, port = _https_endpoint(self.base_url)
        if not host:
            raise ValueError("base_url does not contain a host name")
        try:
            raw_socket = socket.create_connection((host, port), self.timeout)
            with raw_socket:
                with self.context.wrap_socket(raw_socket, server_hostname=host) as sock:
                    der_certificate = sock.getpeercert(binary_form=True)
        except OSError as exc:
            raise RuntimeError(
                f"Failed to read current FRITZ!Box certificate: {exc}"
            ) from exc
        if not der_certificate:
            raise RuntimeError("FRITZ!Box did not present an HTTPS certificate")
        return x509.load_der_x509_certificate(der_certificate)


def _bundle_path(base_dir: str, name: str, output_dir: str | None) -> str:
    """Derive the FritzBox bundle path."""
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    return f"{directory}/{name}-fritzbox.pem"


def _params(params: dict) -> dict:
    """Merge certificate and deploy dictionaries into explicit module params."""
    certificate = dict(params.get("certificate") or {})
    deploy = dict(certificate.get("fritzbox_deploy") or {})
    deploy.update(dict(params.get("deploy") or {}))

    result = dict(params)
    if result.get("output_dir") is None and certificate.get("output_dir") is not None:
        result["output_dir"] = certificate["output_dir"]
    for key in (
        "base_url",
        "username",
        "password",
        "bundle_path",
        "timeout",
        "validate_certs",
        "force",
    ):
        if deploy.get(key) is not None:
            result[key] = deploy[key]
    if result.get("timeout") is None:
        result["timeout"] = 30
    if result.get("validate_certs") is None:
        result["validate_certs"] = True
    if not result.get("bundle_path"):
        result["bundle_path"] = _bundle_path(
            result["base_dir"], result["name"], result.get("output_dir")
        )
    return result


def _load_bundle(path: str) -> bytes:
    """Read and normalize the FritzBox PEM bundle."""
    return read_file(path).strip() + b"\n"


def _leaf_certificate(bundle: bytes) -> x509.Certificate:
    """Return the first certificate from the FritzBox PEM bundle."""
    match = CERTIFICATE_RE.search(bundle)
    if match is None:
        raise ValueError("FritzBox bundle does not contain a certificate")
    return x509.load_pem_x509_certificate(match.group(0))


def _private_key_pem(bundle: bytes) -> bytes:
    """Extract the first private key PEM block from a bundle."""
    match = PRIVATE_KEY_RE.search(bundle)
    if match is None:
        raise ValueError("FritzBox bundle does not contain a private key")
    return match.group(0)


def _private_key_is_encrypted(key_pem: bytes) -> bool:
    """Return whether a PEM private key block is encrypted."""
    first_line = key_pem.splitlines()[0]
    return b"ENCRYPTED" in first_line or b"Proc-Type: 4,ENCRYPTED" in key_pem


def _validate_bundle(bundle: bytes) -> None:
    """Validate that the bundle contains certificates and an RSA private key."""
    certificates = CERTIFICATE_RE.findall(bundle)
    if not certificates:
        raise ValueError("FritzBox bundle does not contain a certificate")
    for certificate in certificates:
        x509.load_pem_x509_certificate(certificate)

    key_pem = _private_key_pem(bundle)
    if _private_key_is_encrypted(key_pem):
        raise ValueError("FRITZ!OS certificate import requires an unencrypted RSA key")
    try:
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )
    except TypeError as exc:
        raise ValueError("FritzBox bundle private key is not readable") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("FRITZ!OS certificate import requires an RSA private key")


def _same_certificate(first: x509.Certificate, second: x509.Certificate) -> bool:
    """Return whether two certificates have the same SHA-256 fingerprint."""
    return first.fingerprint(hashes.SHA256()) == second.fingerprint(hashes.SHA256())


def _multipart_body(boundary: str, sid: str, bundle: bytes) -> bytes:
    """Build the multipart/form-data upload body for firmwarecfg."""
    boundary_bytes = boundary.encode("ascii")
    return b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="sid"\r\n\r\n',
            sid.encode("ascii"),
            b"\r\n--" + boundary_bytes + b"\r\n",
            (
                b'Content-Disposition: form-data; name="BoxCertImportFile"; '
                b'filename="BoxCert.pem"\r\n'
            ),
            b"Content-Type: application/octet-stream\r\n\r\n",
            bundle,
            b"\r\n--" + boundary_bytes + b"--\r\n",
        ]
    )


def _import_succeeded(response: str) -> bool:
    """Return whether the FRITZ!OS import response contains a success marker."""
    return any(marker in response for marker in SUCCESS_MARKERS)


def run_module():
    """Run the Ansible module for FritzBox certificate deployment."""
    module = AnsibleModule(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "certificate": {"type": "dict", "no_log": True},
            "deploy": {"type": "dict", "no_log": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "bundle_path": {"type": "path"},
            "base_url": {"type": "str"},
            "username": {"type": "str"},
            "password": {"type": "str", "no_log": True},
            "timeout": {"type": "int"},
            "validate_certs": {"type": "bool"},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )

    client: FritzBoxClient | None = None
    try:
        params = _params(module.params)
        for key in ("base_url", "username", "password"):
            if not params.get(key):
                raise ValueError(f"FritzBox deployment requires {key}")
        bundle = _load_bundle(params["bundle_path"])
        _validate_bundle(bundle)
        desired_certificate = _leaf_certificate(bundle)
        client = FritzBoxClient(
            base_url=params["base_url"],
            username=params["username"],
            password=params["password"],
            timeout=params["timeout"],
            validate_certs=params["validate_certs"],
        )
        if not params["force"] and _same_certificate(
            desired_certificate,
            client.current_certificate(),
        ):
            module.exit_json(changed=False, path=params["bundle_path"])
        client.login()
        client.import_certificate(bundle)
    except Exception as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    finally:
        if client is not None:
            client.logout()

    module.exit_json(changed=True, path=params["bundle_path"])


def main():
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
