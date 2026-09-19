"""Flipper Zero front-end backends.

``get_bridge("mock")`` needs no hardware and is what the whole pipeline runs on from a
clean clone. ``get_bridge("flipper-cli")`` drives a real Flipper Zero over its serial
CLI. Both return :class:`~policyprobe.schema.Observation` objects, so nothing downstream
knows or cares which was used.
"""

from __future__ import annotations

from .base import Bridge
from .mock import MockBridge


def get_bridge(backend: str = "mock", **kwargs) -> Bridge:
    """Return a bridge backend by name."""
    if backend == "mock":
        return MockBridge(**kwargs)
    if backend in ("flipper-cli", "flipper"):
        from .flipper_cli import FlipperCLIBridge   # imported lazily: needs pyserial + hardware
        return FlipperCLIBridge(**kwargs)
    raise ValueError(f"unknown bridge backend {backend!r}")


__all__ = ["Bridge", "MockBridge", "get_bridge"]
