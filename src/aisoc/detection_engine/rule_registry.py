"""Detection rule registry, mirroring the normalizer registry pattern.

Rules self-register at import time via the :func:`register` class decorator.
``register_all()`` imports the rules package so its modules register; the
engine and tests call it to populate the registry deterministically.
"""

from __future__ import annotations

from collections.abc import Callable

from aisoc.detection_engine.base import Rule

_REGISTRY: dict[str, type[Rule]] = {}


def register(rule_id: str) -> Callable[[type[Rule]], type[Rule]]:
    """Register a Rule implementation under its ``rule_id`` (the category)."""

    def decorator(cls: type[Rule]) -> type[Rule]:
        if getattr(cls, "rule_id", None) != rule_id:
            raise ValueError(f"rule {cls.__name__} rule_id does not match {rule_id}")
        _REGISTRY[rule_id] = cls
        return cls

    return decorator


def get_rule(rule_id: str) -> Rule | None:
    """Return an instantiated rule, or ``None`` when unregistered."""
    cls = _REGISTRY.get(rule_id)
    return cls() if cls is not None else None


def get_rules() -> list[Rule]:
    """Return all registered rules, one instance each, in insertion order."""
    return [cls() for cls in _REGISTRY.values()]


def register_all() -> None:
    """Import rule modules so their ``@register`` decorators run."""
    from aisoc.detection_engine.rules import (  # noqa: F401  (import side effect)
        host_behavior,
        ioc_match,
        ssh_bruteforce,
        web_recon_scan,
        web_request_anomalies,
    )


__all__ = ["get_rule", "get_rules", "register", "register_all"]
