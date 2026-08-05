from __future__ import annotations

import os
import socket
import ssl
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from blue_team.agent_core import (
    AgentCertificateIdentity,
    AgentIdentityError,
    AgentIdentityStore,
    CloneDetectedError,
    LocalCertificateAuthority,
    compute_machine_binding,
    create_agent_csr,
    enrollment_token_id,
    enrollment_token_matches,
    issue_enrollment_token,
    sign_rotation_challenge,
    validate_agent_certificate,
    verify_rotation_proof,
)
from blue_team.domain import AgentEnrollmentCreate, AgentRegistrationTokenCreate

NOW = datetime(2026, 8, 3, 12, tzinfo=UTC)
HARDWARE_BINDING = "a" * 64


def _identity(*, tenant_id: str = "ten_primary1") -> AgentCertificateIdentity:
    return AgentCertificateIdentity(
        tenant_id=tenant_id,
        host_id="host_primary1",
        agent_id="agent_primary1",
        installation_id="inst_primary",
        hardware_binding=HARDWARE_BINDING,
    )


def _agent_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_ca_ignores_csr_claims_and_binds_server_identity() -> None:
    ca = LocalCertificateAuthority.generate(now=NOW)
    key = _agent_key()
    csr = create_agent_csr(
        key,
        common_name="attacker-controlled-name",
        claimed_san_uris=("spiffe://attacker.invalid/admin",),
    )

    issued = ca.issue_agent_certificate(csr, _identity(), now=NOW)
    certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode("ascii"))
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

    assert sans.get_values_for_type(x509.UniformResourceIdentifier) == list(_identity().san_uris)
    assert "attacker.invalid" not in issued.certificate_pem
    assert (
        validate_agent_certificate(
            issued.certificate_pem,
            issued.ca_certificate_pem,
            _identity(),
            now=NOW,
            expected_serial_number=issued.serial_number,
            expected_fingerprint_sha256=issued.fingerprint_sha256,
        ).public_key_sha256
        == issued.public_key_sha256
    )

    with pytest.raises(AgentIdentityError, match="SAN identity"):
        validate_agent_certificate(
            issued.certificate_pem,
            issued.ca_certificate_pem,
            _identity(tenant_id="ten_other001"),
            now=NOW,
        )


def test_certificate_expiry_revocation_and_rotation_proof_are_enforced() -> None:
    ca = LocalCertificateAuthority.generate(now=NOW)
    old_key = _agent_key()
    old = ca.issue_agent_certificate(
        create_agent_csr(old_key, common_name="ignored"),
        _identity(),
        now=NOW,
        lifetime=timedelta(hours=1),
    )
    new_key = _agent_key()
    new_csr = create_agent_csr(new_key, common_name="also-ignored")
    proof = sign_rotation_challenge(old_key, old.certificate_pem, new_csr)

    verify_rotation_proof(old.certificate_pem, new_csr, proof)
    with pytest.raises(AgentIdentityError, match="rotation proof"):
        verify_rotation_proof(
            old.certificate_pem,
            new_csr,
            sign_rotation_challenge(new_key, old.certificate_pem, new_csr),
        )
    with pytest.raises(AgentIdentityError, match="validity period"):
        validate_agent_certificate(
            old.certificate_pem,
            ca.ca_certificate_pem,
            _identity(),
            now=NOW + timedelta(hours=2),
        )
    with pytest.raises(AgentIdentityError, match="revoked"):
        validate_agent_certificate(
            old.certificate_pem,
            ca.ca_certificate_pem,
            _identity(),
            now=NOW,
            revoked_fingerprints=frozenset({old.fingerprint_sha256}),
        )


def test_local_identity_is_private_stable_and_detects_machine_clone(tmp_path: Path) -> None:
    store = AgentIdentityStore(tmp_path / "identity")
    created = store.load_or_create(HARDWARE_BINDING)
    loaded = store.load_or_create(HARDWARE_BINDING)

    assert loaded.installation_id == created.installation_id
    assert loaded.public_key_sha256 == created.public_key_sha256
    assert loaded.create_csr().startswith("-----BEGIN CERTIFICATE REQUEST-----")
    if os.name != "nt":
        assert stat.S_IMODE(store.key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.metadata_path.stat().st_mode) == 0o600
    with pytest.raises(CloneDetectedError, match="machine binding changed"):
        store.load_or_create("b" * 64)


def test_machine_binding_hashes_machine_and_dmi_values(tmp_path: Path) -> None:
    machine_id = tmp_path / "machine-id"
    product_uuid = tmp_path / "product-uuid"
    board_serial = tmp_path / "board-serial"
    machine_id.write_text("machine-01\n", encoding="utf-8")
    product_uuid.write_text("PRODUCT-01\n", encoding="utf-8")
    board_serial.write_text("BOARD-01\n", encoding="utf-8")

    first = compute_machine_binding(
        machine_id_path=machine_id,
        dmi_paths=(product_uuid, board_serial),
    )
    product_uuid.write_text("PRODUCT-02\n", encoding="utf-8")
    second = compute_machine_binding(
        machine_id_path=machine_id,
        dmi_paths=(product_uuid, board_serial),
    )

    assert len(first) == 64
    assert first != second


def test_one_time_token_is_opaque_and_indexable_without_storing_secret() -> None:
    issued = issue_enrollment_token("enrtok_0123456789abcdef0123456789abcdef")

    assert enrollment_token_id(issued.value) == issued.token_id
    assert enrollment_token_matches(issued.value, issued.token_digest)
    assert issued.value not in repr(issued)
    assert not enrollment_token_matches(f"{issued.value}x", issued.token_digest)
    assert enrollment_token_id("malformed") is None


def test_control_plane_and_certificate_identity_share_agent_identifier_contract() -> None:
    with pytest.raises(ValidationError, match="agent_id"):
        AgentRegistrationTokenCreate(agent_id="agent-01")
    with pytest.raises(ValidationError, match="installation_id"):
        AgentEnrollmentCreate(
            registration_token="x" * 64,
            installation_id="installation-01",
            hardware_binding=HARDWARE_BINDING,
            csr_pem="x" * 128,
        )
    with pytest.raises(AgentIdentityError, match="agent_id"):
        AgentCertificateIdentity(
            tenant_id="ten_primary1",
            host_id="host_primary1",
            agent_id="agent-01",
            installation_id="inst_primary",
            hardware_binding=HARDWARE_BINDING,
        )


def test_ca_must_be_valid_for_the_complete_leaf_lifetime() -> None:
    expired_ca = LocalCertificateAuthority.generate(now=NOW - timedelta(days=4000))
    with pytest.raises(AgentIdentityError, match="CA is not valid"):
        expired_ca.issue_agent_certificate(
            create_agent_csr(_agent_key(), common_name="ignored"),
            _identity(),
            now=NOW,
        )

    ca = LocalCertificateAuthority.generate(now=NOW)
    with pytest.raises(AgentIdentityError, match="CA is not valid"):
        ca.issue_agent_certificate(
            create_agent_csr(_agent_key(), common_name="ignored"),
            _identity(),
            now=NOW + timedelta(days=3640),
            lifetime=timedelta(days=30),
        )


def test_real_tls_requires_a_ca_signed_client_certificate(tmp_path: Path) -> None:
    ca = LocalCertificateAuthority.generate(now=datetime.now(UTC))
    server_key, server_certificate = ca.issue_server_certificate("localhost")
    client_key = _agent_key()
    client = ca.issue_agent_certificate(
        create_agent_csr(client_key, common_name="ignored"),
        _identity(),
    )

    ca_path = tmp_path / "ca.pem"
    server_key_path = tmp_path / "server-key.pem"
    server_certificate_path = tmp_path / "server.pem"
    client_key_path = tmp_path / "client-key.pem"
    client_certificate_path = tmp_path / "client.pem"
    ca_path.write_text(ca.ca_certificate_pem, encoding="ascii")
    server_key_path.write_bytes(server_key)
    server_certificate_path.write_bytes(server_certificate)
    client_key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    client_certificate_path.write_text(client.certificate_pem, encoding="ascii")

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_verify_locations(cafile=str(ca_path))
    server_context.load_cert_chain(str(server_certificate_path), str(server_key_path))

    authenticated_client = ssl.create_default_context(cafile=str(ca_path))
    authenticated_client.load_cert_chain(str(client_certificate_path), str(client_key_path))
    unauthenticated_client = ssl.create_default_context(cafile=str(ca_path))

    assert _tls_exchange(server_context, authenticated_client) == (True, True)
    client_result, server_result = _tls_exchange(server_context, unauthenticated_client)
    assert not (client_result and server_result)


def _tls_exchange(
    server_context: ssl.SSLContext,
    client_context: ssl.SSLContext,
) -> tuple[bool, bool]:
    listener = socket.socket()
    listener.settimeout(5)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    server_result: list[bool] = []

    def serve() -> None:
        try:
            connection, _address = listener.accept()
            with connection, server_context.wrap_socket(connection, server_side=True) as tls:
                received = tls.recv(1)
                tls.sendall(received)
                server_result.append(received == b"x")
        except (OSError, ssl.SSLError):
            server_result.append(False)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client_succeeded = False
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5) as connection,
            client_context.wrap_socket(connection, server_hostname="localhost") as tls,
        ):
            tls.sendall(b"x")
            client_succeeded = tls.recv(1) == b"x"
    except (OSError, ssl.SSLError):
        client_succeeded = False
    thread.join(timeout=5)
    assert not thread.is_alive()
    return client_succeeded, server_result == [True]
