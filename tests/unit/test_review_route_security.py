"""Security tests for the P7 AI review route: advisory lock key derivation."""

from __future__ import annotations

from blue_team.api_server.routes.incidents import _review_lock_key


def test_review_lock_key_is_deterministic() -> None:
    key1 = _review_lock_key("ten_01", "inc_01", 1, "v1")
    key2 = _review_lock_key("ten_01", "inc_01", 1, "v1")
    assert key1 == key2


def test_review_lock_key_is_positive_int64() -> None:
    key = _review_lock_key("ten_01", "inc_01", 1, "v1")
    assert 0 <= key < 2**63
    assert isinstance(key, int)


def test_review_lock_key_differs_by_incident() -> None:
    key_a = _review_lock_key("ten_01", "inc_a", 1, "v1")
    key_b = _review_lock_key("ten_01", "inc_b", 1, "v1")
    assert key_a != key_b


def test_review_lock_key_differs_by_revision() -> None:
    key_r1 = _review_lock_key("ten_01", "inc_01", 1, "v1")
    key_r2 = _review_lock_key("ten_01", "inc_01", 2, "v1")
    assert key_r1 != key_r2


def test_review_lock_key_differs_by_policy_version() -> None:
    key_v1 = _review_lock_key("ten_01", "inc_01", 1, "v1")
    key_v2 = _review_lock_key("ten_01", "inc_01", 1, "v2")
    assert key_v1 != key_v2


def test_review_lock_key_differs_by_tenant() -> None:
    key_a = _review_lock_key("ten_a", "inc_01", 1, "v1")
    key_b = _review_lock_key("ten_b", "inc_01", 1, "v1")
    assert key_a != key_b
