"""Turn observations and inventory attributes into findings in the common schema.

Two sources feed a finding, and keeping them apart matters for the credibility of the
report:

``rf_probe``
    The classifier flagged the weakness from what the Flipper observed. Confidence is the
    model's, and it is carried into the report so an assessor can see which findings rest
    on a marginal read.

``inventory``
    The weakness follows deterministically from a recorded attribute of the access point —
    a Wiegand reader interface, an unsupervised tamper switch, a single factor on a server
    room. Confidence is 1.0 because nothing was inferred.

A compliance report that blurred the two would be claiming certainty it does not have.
"""

from __future__ import annotations

from .. import kb
from ..classify.model import WeaknessClassifier
from ..data.catalog import DEVICE_PROFILES
from ..schema import AccessPoint, Facility, Finding, Observation

# Deterministic rules for the inventory-sourced weaknesses. Each returns (applies, evidence).
INVENTORY_RULES: dict[str, callable] = {}


def _rule(weakness_id: str):
    def deco(fn):
        INVENTORY_RULES[weakness_id] = fn
        return fn
    return deco


@_rule("W-WIRE-CLEARTEXT")
def _wire_cleartext(ap: AccessPoint, _obs: Observation):
    if ap.protocol not in ("rfid_lf", "nfc_hf"):
        return False, ""
    if ap.reader_interface == "wiegand":
        return True, ("Reader-to-controller interface recorded as Wiegand: the decoded "
                      "credential crosses the reader's wiring unauthenticated and in the clear.")
    if ap.reader_interface == "osdp":
        return True, ("Reader-to-controller interface recorded as OSDP with Secure Channel "
                      "not enabled, which leaves the link unauthenticated.")
    return False, ""


@_rule("W-NO-TAMPER")
def _no_tamper(ap: AccessPoint, _obs: Observation):
    if not ap.tamper_supervised:
        return True, "No supervised tamper switch on the reader assembly at this access point."
    return False, ""


@_rule("W-NO-EVENT-LOG")
def _no_log(ap: AccessPoint, _obs: Observation):
    if not ap.events_logged:
        return True, ("Access point is not integrated with the access control platform; no "
                      "retained event is produced for entries through it.")
    return False, ""


@_rule("W-SHARED-CREDENTIAL")
def _shared(ap: AccessPoint, _obs: Observation):
    if ap.shared_credential:
        return True, ("A pooled credential is issued for this access point, so entry events "
                      "cannot be attributed to an individual.")
    return False, ""


@_rule("W-SINGLE-FACTOR-HIGH")
def _single_factor(ap: AccessPoint, _obs: Observation):
    if ap.factors < 2 and ap.zone in ("restricted", "secure"):
        return True, (f"A single possession factor is enforced at a {ap.zone} zone boundary; "
                      "no PIN, biometric or supervised entry is required.")
    return False, ""


@_rule("W-LEGACY-EOL")
def _eol(ap: AccessPoint, _obs: Observation):
    if ap.lifecycle == "eol":
        return True, (f"{ap.device_type} at this access point is recorded as an end-of-life "
                      "generation with no remaining vendor security maintenance.")
    return False, ""


@_rule("W-NO-REVOCATION")
def _no_revocation(ap: AccessPoint, _obs: Observation):
    profile = DEVICE_PROFILES.get(ap.device_type, {})
    if "W-NO-REVOCATION" in profile.get("intrinsic", []):
        return True, (f"{ap.device_type} carries no expiry field and nothing cryptographically "
                      "revocable; revocation depends entirely on the controller allow list.")
    return False, ""


class Normalizer:
    """Produces findings for a facility from observations plus inventory attributes."""

    def __init__(self, classifier: WeaknessClassifier, threshold: float = 0.5):
        self.classifier = classifier
        self.threshold = threshold
        self.weaknesses = kb.weakness_index()

    def _make_finding(self, ap: AccessPoint, device_type: str, weakness_id: str,
                      source: str, confidence: float, evidence: str, index: int) -> Finding:
        w = self.weaknesses[weakness_id]
        return Finding(
            id=f"F-{ap.id.split('-')[-1]}-{index:02d}",
            access_point_id=ap.id,
            access_point_name=ap.name,
            zone=ap.zone,
            protocol=ap.protocol,
            device_type=device_type,
            weakness_id=weakness_id,
            weakness_title=w["title"],
            source=source,
            confidence=round(confidence, 3),
            evidence=evidence,
            base_severity=w["base_severity"],
        )

    def normalize(self, ap: AccessPoint, obs: Observation) -> list[Finding]:
        """Return every finding for one access point."""
        findings: list[Finding] = []
        device_type, device_conf = self.classifier.predict_device(obs)
        flagged = self.classifier.predict_weaknesses(obs, threshold=self.threshold)

        index = 0
        for weakness_id, confidence in sorted(flagged.items()):
            w = self.weaknesses.get(weakness_id)
            if w is None or ap.protocol not in w["protocols"]:
                continue        # the flag does not apply to this protocol; drop it
            index += 1
            findings.append(self._make_finding(
                ap, device_type, weakness_id, "rf_probe", confidence,
                self._rf_evidence(weakness_id, obs, device_type, device_conf), index,
            ))

        for weakness_id, rule in INVENTORY_RULES.items():
            w = self.weaknesses[weakness_id]
            if ap.protocol not in w["protocols"]:
                continue
            applies, evidence = rule(ap, obs)
            if applies:
                index += 1
                findings.append(self._make_finding(
                    ap, device_type, weakness_id, "inventory", 1.0, evidence, index,
                ))
        return findings

    @staticmethod
    def _rf_evidence(weakness_id: str, obs: Observation, device_type: str,
                     device_conf: float) -> str:
        """One sentence an assessor can defend, naming what was actually observed."""
        p = obs.payload
        reads = p.get("n_reads", 0)
        distinct = p.get("distinct_reads", 0)
        base = f"Identified as {device_type} (confidence {device_conf:.2f}). "
        detail = {
            "W-STATIC-ID": f"{reads} repeat reads returned {distinct} distinct payload(s); "
                           "the credential presents a fixed identifier with no challenge.",
            "W-NO-CRYPTO": "No challenge and no authentication round observed in the exchange.",
            "W-BROKEN-CRYPTO": "This generation's proprietary cipher has published practical "
                               "key-recovery attacks (see mapping references).",
            "W-DEFAULT-KEYS": "Read-only authentication succeeded against a stock default-key "
                              "dictionary.",
            "W-FIXED-CODE-RF": f"Counter step observed as {p.get('counter_step')}: the remote "
                               "transmits an identical code on every press.",
            "W-ROLLING-REPLAY": "Rolling counter present, but the exchange is one-way with no "
                                "receiver challenge.",
            "W-SEQUENTIAL-ID": "Identifiers sampled from the same issuing batch differ by a "
                               "near-constant step, indicating sequential allocation.",
            "W-SMALL-NAMESPACE": f"Decoded payload is {p.get('bit_length')} bits against a "
                                 f"population of {p.get('credential_population')} holders.",
            "W-NO-MUTUAL-AUTH": "The credential responded without requiring any proof from the "
                                "reader.",
            "W-MIXED-MODE": "A legacy-format credential was accepted by this reader alongside "
                            "the current format.",
            "W-IR-UNAUTH-CTRL": "The device acted on a replayed capture of its own infrared "
                                "command with no authentication.",
        }.get(weakness_id, "Observed during the authorised probe of this access point.")
        return base + detail


def normalize_facility(facility: Facility, observations: list[Observation],
                       classifier: WeaknessClassifier, threshold: float = 0.5
                       ) -> list[Finding]:
    """Normalise a whole facility's observations into findings."""
    normalizer = Normalizer(classifier, threshold=threshold)
    by_id = {o.access_point_id: o for o in observations}
    findings: list[Finding] = []
    for ap in facility.access_points:
        obs = by_id.get(ap.id)
        if obs is None:
            continue
        findings.extend(normalizer.normalize(ap, obs))
    return findings
