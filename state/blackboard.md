```yaml
tested:
  - target: tenant credential × /api/v1/hosts × cross-tenant host ownership × read × bearer/header variation
    finding_status: closed
    rating: unrated
    evidence: "Post-fix PostgreSQL integration and deployed-container requests: tenant A credential reading tenant B host returned 404; adding X-Tenant-ID for tenant B returned 403; tests/integration/test_p1_api.py reproduces both comparisons."
    next: "Reopen if another authentication mode, batch endpoint, or object API derives tenant_id from caller-controlled headers/body instead of the authenticated principal."
  - target: agent identity × local AgentEnvelope/queue × event tenant/host/boot/sequence × buffer/batch × body variation
    finding_status: closed
    rating: unrated
    evidence: "AgentEnvelope validation rejects mismatched tenant, agent, host, boot, and sequence before enqueue; the SQLite file is bound to one configured tenant/agent/host identity; tests/unit/test_agent_contracts.py and test_agent_queue.py reproduce the negative comparisons."
    next: "Reopen at P2 mTLS/P3 ingest when certificate subject-to-agent/tenant binding and server-side body revalidation are implemented dynamically."
  - target: agent queue × P0/P1/P2/P3 event priority × capacity/retry/corruption × state transition × queue pressure
    finding_status: closed
    rating: unrated
    evidence: "Capacity tests show P0 enters protection mode with dropped.p0=0; P2 replaces auditable P3 data; partial ACK and network release reuse the immutable batch ID/digest; corrupt protected data is quarantined and raises protection. Linux container smoke ran as UID 10001 with database mode 0600 and recovered/ACKed two events after restart."
    next: "Reopen for real disk-full/WAL fault injection, process kill during fsync, and receiver-side ACK/DLQ integration."
  - target: tenant/anonymous Agent × registration API × tenant Host/CSR × enroll/replay × tenant, token, CSR identity variation
    finding_status: closed
    rating: unrated
    evidence: "tests/integration/test_agent_identity.py: tenant B credential requesting tenant A Host token returned 404; the database contained only the token digest; an invalid CSR returned 401 without consumption; a valid P-256 CSR with forged Subject/SAN enrolled using server-side identity; replay returned 401."
    next: "Reopen when registration is exposed through a TLS proxy or another Host creation/batch enrollment path; confirm proxy routing cannot alter signer or tenant context."
  - target: registered Agent × certificate lifecycle service × Agent identity/certificate × rotate/revoke/re-enroll × proof and certificate state
    finding_status: closed
    rating: unrated
    evidence: "Real ssl sockets required a CA-signed client certificate. PostgreSQL integration rejected rotation signed by the new/wrong key, accepted proof from the old private key, rejected the old certificate after rotation, accepted the new certificate, rejected it after tenant revocation, and accepted a newly authorized installation only after explicit re-enrollment."
    next: "Reopen at Ingest integration and validate peer-certificate extraction from the actual TLS server; never accept a caller-supplied certificate header without a trusted proxy contract."
  - target: copied Agent image × local identity/session service × installation and certificate × concurrent use × machine binding and lease state
    finding_status: lead
    rating: unrated
    evidence: "Local store comparison raised clone detected when the current machine/DMI digest differed. Two concurrent PostgreSQL transactions using the same valid certificate produced one lease and one active_identity_lease conflict. A real mTLS Ingest gateway now exists (src/blue_team/ingest_gateway, src/blue_team/agent_core/transport.py): every heartbeat/events connection terminates mutual TLS, reads the client certificate, calls renew_agent_session (storage/agent_identity.py) to renew-or-acquire the single-active lease, and revalidates batch tenant/agent/host against the certificate identity. Verified 2026-08-04 against a real PostgreSQL 17 container (Docker Desktop Linux Engine) via tests/integration/test_ingest_mtls.py: enroll→heartbeat→batch→ACK produced 2 agent_events + 1 agent_heartbeat + 1 agent_session + 2 immutable evidence objects, accepted_sequence=sequence_end, and a second connection presenting the same cert with no session value was rejected 409 while the lease was active. tests/unit/test_transport.py covers the mTLS client (ssl context, X-Agent-Session header, ack/release, status rejection)."
    next: "The lease is enforced per authenticated connection at the gateway and tested at the aiohttp/httpx level; tests/integration/test_ingest_mtls.py and tests/smoke/linux_ingest_e2e_smoke.py both reproduce enroll→heartbeat→batch→ACK→clone-reject-409 under a real PostgreSQL (Docker Linux Engine) and are green (2026-08-04). Remaining open item is a real VM disk-copy clone where the original and clone cannot remain simultaneously active across a long window, plus the real Linux VM matrix (eBPF/auditd/DEB/RPM/systemd). Software binding still cannot resist root plus fully replicated hardware identifiers and the leased session value; evaluate TPM-backed attestation separately."
  - target: Agent runtime × Collector/heartbeat/SQLite queue × collection admission and health × lifecycle/pressure/failure × state transition
    finding_status: closed
    rating: unrated
    evidence: "test_agent_runtime.py covers deterministic runtime states and a real SQLite P0 protection transition. test_agent_process.py and test_agent_supervisor.py add a real blue-team-agent entry, private bounded config, single-instance state lock, fsync lifecycle/Heartbeat journals, ordered started/healthy protocol, separate startup/health/TERM/KILL deadlines, combined output budget, literal argv, sanitized environment, closed FDs, and process-group cleanup. Linux UID 10001 ran 43 relevant pytest cases plus tests/smoke/linux_agent_supervisor_smoke.py against image sha256:52287cf75a644a8670be48e70765636dacf487ab2297737868945c148fe82e6c: real CLI stopped cleanly, a competing instance was rejected, a TERM-ignoring probe was killed/reaped, hardlink substitution was rejected, and state files remained 0600."
    next: "Reopen when Collector drivers become subprocesses or Heartbeat uses mTLS network transport; fault blocked drivers, transport timeout/replay, journal disk-full/rotation, supervisor restart, and kill during each persisted lifecycle transition."
  - target: release signer × Agent verifier/installer/state store × artifact tar/content/target/version × verify/stage/health/activate/rollback/recover × key, kind, path, content, sequence, approval, lock, and revision variation
    finding_status: closed
    rating: unrated
    evidence: "test_agent_releases.py and test_agent_installer.py verify signed persistence plus health-gated tar install/upgrade, including signature/target/replay/floor/approval/path/symlink/hardlink/size/content/journal/lock variations. InstalledReleaseProcessHealthCheck resolves only the manifest-declared executable from the uncommitted candidate and invokes fixed health-probe argv through the bounded supervisor. Linux UID 10001 dynamically installed a wrapper around the real Agent CLI, committed only after ordered startup/health and graceful stop, then rejected a health-timeout upgrade, deleted its candidate, and preserved the old active/state and queue sentinel. Current PostgreSQL Windows gate: 121 passed/8 platform cases skipped; Linux relevant gate: 43 passed plus standalone smoke."
    next: "Reopen at downloader/systemd/policy integration. Test interrupted or substituted downloads, kill -9 and power loss at each fsync/rename boundary, privileged updater versus unprivileged Agent ownership, bypass writers outside the installer lock, key rotation/revocation, fleet rollout stop conditions, and real DEB/RPM/tar install/upgrade/rollback/uninstall on the fixed Linux VM matrix."
```
