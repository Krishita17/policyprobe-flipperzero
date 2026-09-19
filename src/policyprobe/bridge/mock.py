"""Hardware-free bridge backend.

Renders each access point's true configuration into a noisy observation, exactly as the
hardware backend would render a real read. This is the default backend so that every
figure, table and report in the repository is reproducible without a Flipper Zero.
"""

from __future__ import annotations

import random

from ..schema import AccessPoint, Observation
from ..data.observations import simulate_observation
from .base import Bridge


class MockBridge(Bridge):
    """Deterministic, seeded simulation of the Flipper front-end."""

    name = "mock"

    def __init__(self, seed: int = 1234, noise: dict[str, float] | None = None,
                 sequential_sampling: bool = True):
        self.rng = random.Random(seed)
        self.noise = noise
        self.sequential_sampling = sequential_sampling

    def probe(self, access_point: AccessPoint) -> Observation:
        sequential = self.sequential_sampling and (
            "W-SEQUENTIAL-ID" in access_point.ground_truth_weaknesses
        )
        return simulate_observation(
            access_point, self.rng, noise=self.noise, sequential_neighbourhood=sequential
        )
