# Rust helpers (optional accelerator)

This directory holds the optional Rust extension that accelerates a few pure,
CPU-bound leaf helpers used by the Python platform. It is **not required** to run
the Blue Team AI Agent: the Python package imports the compiled extension when
present and otherwise falls back to the standard-library `hashlib` / `hmac`
implementations, producing byte-identical output (verified by
`tests/unit/test_rust_hash.py`).

## Layout

```
rust/blue-team-rust/
  Cargo.toml      PyO3 extension crate (cdylib, abi3-py312)
  src/lib.rs       sha256_hex / sha256_bytes / hmac_sha256_hex / version
```

The extension is exposed to Python as the importable module `blue_team_rust` and
wrapped by `src/blue_team/_rusthash.py`, which provides the `rust_available()`
probes and the `hashlib`/`hmac` fallbacks. Call sites must never assume the
extension is present — the fallback is the correctness baseline.

## Build and install (Kali / Linux)

Requires the Rust toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
and `maturin`:

```bash
# install maturin (once): uv tool install maturin
source "$HOME/.cargo/env"
uv tool install maturin
# build + install the extension into the project venv (.venv) as an editable wheel
VIRTUAL_ENV="$(pwd)/.venv" maturin develop --manifest-path rust/blue-team-rust/Cargo.toml
```

After this, `uv run python -c "import blue_team_rust; print(blue_team_rust.version())"`
succeeds and `blue_team._rusthash.rust_available()` returns `True`.

To run without the extension (pure-Python fallback), simply do not build/install
it; all tests still pass because the wrapper falls back to `hashlib` / `hmac`.

## Wired call sites

- `src/blue_team/agent_core/contracts.py` — `canonical_envelope_bytes` integrity hash (`sha256_hex`).
- `src/blue_team/credentials.py` — bearer-token SHA-256 digest (`sha256_hex`).
- `src/blue_team/notification_engine/webhook.py` — signed-webhook HMAC-SHA256 (`hmac_sha256_hex`) and destination id (`sha256_hex`).

## Testing

```bash
uv run pytest tests/unit/test_rust_hash.py -v
```

The parametrized cases compare the wrapper against `hashlib` / `hmac` directly,
so they exercise the Rust path when the extension is built and the fallback
otherwise.
