"""Agent key storage and X.509 identity primitives for the P2 mTLS boundary."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, Self
from urllib.parse import quote
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from blue_team.domain.identifiers import is_valid_identifier


class AgentIdentityError(ValueError):
    """Raised when an Agent identity or certificate violates its security contract."""


class CloneDetectedError(AgentIdentityError):
    """Raised when a persisted installation is observed on a different machine binding."""


class IdentityStoreError(AgentIdentityError):
    """Raised when local identity material is incomplete or insecure."""


@dataclass(frozen=True, slots=True)
class AgentCertificateIdentity:
    tenant_id: str
    host_id: str
    agent_id: str
    installation_id: str
    hardware_binding: str

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("host_id", self.host_id),
            ("agent_id", self.agent_id),
            ("installation_id", self.installation_id),
        ):
            if not is_valid_identifier(name, value):
                raise AgentIdentityError(f"invalid {name}")
        if len(self.hardware_binding) != 64 or any(
            character not in "0123456789abcdef" for character in self.hardware_binding
        ):
            raise AgentIdentityError("hardware_binding must be a lowercase SHA-256 digest")

    @property
    def san_uris(self) -> tuple[str, ...]:
        return (
            "spiffe://blue-team.local/tenant/"
            f"{quote(self.tenant_id, safe='')}/agent/{quote(self.agent_id, safe='')}",
            f"urn:blue-team:host:{quote(self.host_id, safe='')}",
            f"urn:blue-team:installation:{quote(self.installation_id, safe='')}",
            f"urn:blue-team:hardware:{self.hardware_binding}",
        )


@dataclass(frozen=True, slots=True)
class IssuedAgentCertificate:
    certificate_pem: str
    ca_certificate_pem: str
    serial_number: str
    fingerprint_sha256: str
    public_key_sha256: str
    not_valid_before: datetime
    not_valid_after: datetime


class CertificateSigner(Protocol):
    @property
    def ca_certificate_pem(self) -> str: ...

    def issue_agent_certificate(
        self,
        csr_pem: str,
        identity: AgentCertificateIdentity,
        *,
        now: datetime | None = None,
        lifetime: timedelta = timedelta(days=30),
    ) -> IssuedAgentCertificate: ...

    def issue_server_certificate(
        self,
        hostname: str,
        *,
        now: datetime | None = None,
        lifetime: timedelta = timedelta(days=30),
    ) -> tuple[bytes, bytes]: ...


class LocalCertificateAuthority:
    """P-256 CA implementation for development, tests, and injected file-backed use."""

    def __init__(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        certificate: x509.Certificate,
    ) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise AgentIdentityError("the CA key must use P-256")
        certificate_public_key = certificate.public_key()
        if not isinstance(certificate_public_key, ec.EllipticCurvePublicKey):
            raise AgentIdentityError("the CA certificate must use an EC public key")
        if private_key.public_key().public_numbers() != certificate_public_key.public_numbers():
            raise AgentIdentityError("the CA private key does not match its certificate")
        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as error:
            raise AgentIdentityError("the signer certificate extensions are incomplete") from error
        if not constraints.ca or not usage.key_cert_sign:
            raise AgentIdentityError("the signer certificate is not a CA")
        self._private_key = private_key
        self.certificate = certificate

    @classmethod
    def generate(
        cls,
        *,
        common_name: str = "Blue Team Agent Development CA",
        now: datetime | None = None,
    ) -> Self:
        issued_at = _aware(now or datetime.now(UTC))
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(issued_at - timedelta(minutes=1))
            .not_valid_after(issued_at + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256())
        )
        return cls(key, certificate)

    @classmethod
    def from_pem(cls, private_key_pem: bytes, certificate_pem: bytes) -> Self:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise AgentIdentityError("the CA private key must be elliptic-curve")
        return cls(key, x509.load_pem_x509_certificate(certificate_pem))

    @property
    def ca_certificate_pem(self) -> str:
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def issue_agent_certificate(
        self,
        csr_pem: str,
        identity: AgentCertificateIdentity,
        *,
        now: datetime | None = None,
        lifetime: timedelta = timedelta(days=30),
    ) -> IssuedAgentCertificate:
        issued_at = _aware(now or datetime.now(UTC))
        if lifetime <= timedelta(0) or lifetime > timedelta(days=90):
            raise AgentIdentityError("agent certificate lifetime must be between 0 and 90 days")
        self._require_valid_issuance_window(issued_at, lifetime)
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise AgentIdentityError("invalid PEM certificate signing request") from error
        if not csr.is_signature_valid:
            raise AgentIdentityError("CSR signature is invalid")
        public_key = csr.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise AgentIdentityError("agent CSR keys must use P-256")

        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity.agent_id)]))
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(issued_at - timedelta(minutes=1))
            .not_valid_after(issued_at + lifetime)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(uri) for uri in identity.san_uris]
                ),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._private_key.public_key()),
                False,
            )
            .sign(self._private_key, hashes.SHA256())
        )
        return _issued_certificate(certificate, self.ca_certificate_pem)

    def issue_server_certificate(
        self,
        hostname: str,
        *,
        now: datetime | None = None,
        lifetime: timedelta = timedelta(days=30),
    ) -> tuple[bytes, bytes]:
        """Issue a serverAuth-only leaf for real TLS boundary tests or local deployments."""
        issued_at = _aware(now or datetime.now(UTC))
        if not hostname or lifetime <= timedelta(0) or lifetime > timedelta(days=90):
            raise AgentIdentityError("invalid TLS server certificate request")
        self._require_valid_issuance_window(issued_at, lifetime)
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(issued_at - timedelta(minutes=1))
            .not_valid_after(issued_at + lifetime)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .sign(self._private_key, hashes.SHA256())
        )
        return (
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            certificate.public_bytes(serialization.Encoding.PEM),
        )

    def _require_valid_issuance_window(self, issued_at: datetime, lifetime: timedelta) -> None:
        if (
            issued_at < self.certificate.not_valid_before_utc
            or issued_at > self.certificate.not_valid_after_utc
            or issued_at + lifetime > self.certificate.not_valid_after_utc
        ):
            raise AgentIdentityError("the CA is not valid for the requested certificate lifetime")


def create_agent_csr(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    common_name: str,
    claimed_san_uris: tuple[str, ...] = (),
) -> str:
    """Create a signed P-256 CSR; claimed SANs are intentionally untrusted by the CA."""
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise AgentIdentityError("agent keys must use P-256")
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if claimed_san_uris:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(uri) for uri in claimed_san_uris]
            ),
            critical=False,
        )
    return (
        builder.sign(private_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def validate_agent_certificate(
    certificate_pem: str,
    ca_certificate_pem: str,
    identity: AgentCertificateIdentity,
    *,
    now: datetime | None = None,
    expected_serial_number: str | None = None,
    expected_fingerprint_sha256: str | None = None,
    revoked_fingerprints: frozenset[str] = frozenset(),
) -> IssuedAgentCertificate:
    """Verify the cryptographic chain and every server-authored Agent identity field."""
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise AgentIdentityError("invalid PEM certificate") from error
    checked_at = _aware(now or datetime.now(UTC))
    if certificate.issuer != ca_certificate.subject:
        raise AgentIdentityError("certificate issuer does not match the configured CA")
    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, ec.EllipticCurvePublicKey) or not isinstance(
        ca_public_key.curve, ec.SECP256R1
    ):
        raise AgentIdentityError("configured CA does not use a P-256 public key")
    try:
        ca_constraints = ca_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        ca_usage = ca_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise AgentIdentityError("configured CA certificate extensions are incomplete") from error
    if not ca_constraints.ca or not ca_usage.key_cert_sign:
        raise AgentIdentityError("configured certificate is not authorized to sign certificates")
    if (
        checked_at < ca_certificate.not_valid_before_utc
        or checked_at > ca_certificate.not_valid_after_utc
    ):
        raise AgentIdentityError("configured CA is outside its validity period")
    signature_hash_algorithm = certificate.signature_hash_algorithm
    if signature_hash_algorithm is None:
        raise AgentIdentityError("certificate signature hash algorithm is unavailable")
    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(signature_hash_algorithm),
        )
    except InvalidSignature as error:
        raise AgentIdentityError("certificate signature is invalid") from error

    if (
        checked_at < certificate.not_valid_before_utc
        or checked_at > certificate.not_valid_after_utc
        or certificate.not_valid_before_utc < ca_certificate.not_valid_before_utc
        or certificate.not_valid_after_utc > ca_certificate.not_valid_after_utc
    ):
        raise AgentIdentityError("certificate is outside its validity period")
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != identity.agent_id:
        raise AgentIdentityError("certificate subject is not bound to the expected agent")
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        constraints_extension = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        usage_extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        extended_usage_extension = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        )
    except x509.ExtensionNotFound as error:
        raise AgentIdentityError("agent certificate extensions are incomplete") from error
    if tuple(san.get_values_for_type(x509.UniformResourceIdentifier)) != identity.san_uris:
        raise AgentIdentityError("certificate SAN identity does not match the expected binding")
    if not constraints_extension.critical or constraints_extension.value.ca:
        raise AgentIdentityError("agent certificate cannot be a CA")
    usage = usage_extension.value
    if (
        not usage_extension.critical
        or not usage.digital_signature
        or usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or usage.key_cert_sign
        or usage.crl_sign
    ):
        raise AgentIdentityError("agent certificate key usage is invalid")
    extended_usage = extended_usage_extension.value
    if not extended_usage_extension.critical:
        raise AgentIdentityError("agent certificate extended key usage must be critical")
    if set(extended_usage) != {ExtendedKeyUsageOID.CLIENT_AUTH}:
        raise AgentIdentityError("agent certificate must be restricted to client authentication")

    issued = _issued_certificate(certificate, ca_certificate_pem)
    if expected_serial_number is not None and issued.serial_number != expected_serial_number:
        raise AgentIdentityError("certificate serial number does not match the identity record")
    if (
        expected_fingerprint_sha256 is not None
        and issued.fingerprint_sha256 != expected_fingerprint_sha256
    ):
        raise AgentIdentityError("certificate fingerprint does not match the identity record")
    if issued.fingerprint_sha256 in revoked_fingerprints:
        raise AgentIdentityError("certificate has been revoked")
    return issued


def rotation_challenge(old_certificate_pem: str, new_csr_pem: str) -> bytes:
    certificate = x509.load_pem_x509_certificate(old_certificate_pem.encode("ascii"))
    csr = x509.load_pem_x509_csr(new_csr_pem.encode("ascii"))
    return (
        b"blue-team-agent-rotation-v1\x00"
        + certificate.fingerprint(hashes.SHA256())
        + hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).digest()
    )


def sign_rotation_challenge(
    private_key: ec.EllipticCurvePrivateKey,
    old_certificate_pem: str,
    new_csr_pem: str,
) -> bytes:
    return private_key.sign(
        rotation_challenge(old_certificate_pem, new_csr_pem),
        ec.ECDSA(hashes.SHA256()),
    )


def verify_rotation_proof(
    old_certificate_pem: str,
    new_csr_pem: str,
    signature: bytes,
) -> None:
    certificate = x509.load_pem_x509_certificate(old_certificate_pem.encode("ascii"))
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise AgentIdentityError("old certificate does not contain an EC key")
    try:
        public_key.verify(
            signature,
            rotation_challenge(old_certificate_pem, new_csr_pem),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as error:
        raise AgentIdentityError("rotation proof does not match the old certificate") from error


@dataclass(frozen=True, slots=True)
class LocalAgentIdentity:
    installation_id: str
    hardware_binding: str
    private_key: ec.EllipticCurvePrivateKey

    @property
    def public_key_sha256(self) -> str:
        return public_key_sha256(self.private_key.public_key())

    def create_csr(self, *, common_name: str | None = None) -> str:
        return create_agent_csr(
            self.private_key,
            common_name=common_name or self.installation_id,
        )


class AgentIdentityStore:
    """Persist a non-export-protected software key with clone-detection metadata."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.key_path = root / "agent-key.pem"
        self.metadata_path = root / "identity.json"

    def load_or_create(self, hardware_binding: str) -> LocalAgentIdentity:
        _validate_hardware_binding(hardware_binding)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _require_private_directory(self.root)
        key_exists = self.key_path.exists()
        metadata_exists = self.metadata_path.exists()
        if key_exists != metadata_exists:
            raise IdentityStoreError(
                "local identity is incomplete; explicit re-enrollment is required"
            )
        if key_exists:
            return self._load(hardware_binding)

        key = ec.generate_private_key(ec.SECP256R1())
        installation_id = f"inst_{uuid4().hex}"
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        metadata = json.dumps(
            {
                "format_version": 1,
                "hardware_binding": hardware_binding,
                "installation_id": installation_id,
                "public_key_sha256": public_key_sha256(key.public_key()),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            _exclusive_write(self.key_path, key_pem, 0o600)
            _exclusive_write(self.metadata_path, metadata, 0o600)
        except OSError as error:
            raise IdentityStoreError("failed to create local identity securely") from error
        return LocalAgentIdentity(installation_id, hardware_binding, key)

    def _load(self, hardware_binding: str) -> LocalAgentIdentity:
        _require_private_file(self.key_path)
        _require_private_file(self.metadata_path)
        try:
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict) or metadata.get("format_version") != 1:
                raise IdentityStoreError("unsupported local identity metadata")
            installation_id = str(metadata["installation_id"])
            recorded_binding = str(metadata["hardware_binding"])
            recorded_public_key = str(metadata["public_key_sha256"])
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
            raise IdentityStoreError("local identity material is invalid") from error
        if recorded_binding != hardware_binding:
            raise CloneDetectedError(
                "machine binding changed; copied identity cannot be used without re-enrollment"
            )
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise IdentityStoreError("local Agent key must use P-256")
        if public_key_sha256(key.public_key()) != recorded_public_key:
            raise IdentityStoreError("local key does not match its identity metadata")
        return LocalAgentIdentity(installation_id, recorded_binding, key)


def compute_machine_binding(
    *,
    machine_id_path: Path = Path("/etc/machine-id"),
    dmi_paths: tuple[Path, ...] = (
        Path("/sys/class/dmi/id/product_uuid"),
        Path("/sys/class/dmi/id/board_serial"),
    ),
) -> str:
    """Hash stable OS/DMI identifiers without persisting their raw values."""
    components: list[tuple[str, str]] = []
    sources = (
        ("machine-id", machine_id_path),
        *((f"dmi-{index}", path) for index, path in enumerate(dmi_paths)),
    )
    for label, path in sources:
        try:
            value = path.read_text(encoding="utf-8").strip().lower()
        except (OSError, UnicodeError):
            continue
        if value and "\x00" not in value and len(value) <= 256:
            components.append((label, value))
    if not components or components[0][0] != "machine-id":
        raise IdentityStoreError("a readable machine-id is required for machine binding")
    digest = hashlib.sha256()
    for label, value in components:
        digest.update(label.encode("ascii"))
        digest.update(b"\x00")
        digest.update(value.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


def public_key_sha256(public_key: ec.EllipticCurvePublicKey) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def _issued_certificate(
    certificate: x509.Certificate,
    ca_certificate_pem: str,
) -> IssuedAgentCertificate:
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise AgentIdentityError("agent certificate does not use a P-256 key")
    return IssuedAgentCertificate(
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_certificate_pem=ca_certificate_pem,
        serial_number=format(certificate.serial_number, "x"),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        public_key_sha256=public_key_sha256(public_key),
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AgentIdentityError("certificate timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _validate_hardware_binding(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise AgentIdentityError("hardware binding must be a lowercase SHA-256 digest")


def _exclusive_write(path: Path, content: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _require_private_file(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise IdentityStoreError("identity files must be regular files, not links")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise IdentityStoreError("identity files must not be accessible by group or other users")


def _require_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise IdentityStoreError("identity root must be a private directory, not a link")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise IdentityStoreError("identity root must not be accessible by group or other users")
