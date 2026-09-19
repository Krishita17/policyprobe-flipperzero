"""Bridge interface shared by the mock and hardware backends."""

from __future__ import annotations

import abc

from ..schema import AccessPoint, Observation


class Bridge(abc.ABC):
    """Acquires observations from access points.

    A bridge is responsible only for acquisition. It performs no interpretation: deciding
    that a credential is weak is the classifier's job, and deciding which control that
    affects is the mapping engine's.
    """

    name: str = "bridge"

    @abc.abstractmethod
    def probe(self, access_point: AccessPoint) -> Observation:
        """Probe a single access point and return a raw observation."""

    def probe_all(self, access_points: list[AccessPoint]) -> list[Observation]:
        """Probe every access point in order."""
        return [self.probe(ap) for ap in access_points]

    def close(self) -> None:      # pragma: no cover - trivial
        """Release any hardware resources."""
