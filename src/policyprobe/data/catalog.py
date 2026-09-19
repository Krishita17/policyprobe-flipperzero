"""Credential technology catalogue.

Each entry describes one credential generation an assessor realistically meets in the
field: which protocol it speaks, which weaknesses are intrinsic to the generation, and
the signal characteristics a Flipper Zero observes when reading it.

The ``signal`` block is what the mock bridge renders into an observation and what the
classifier learns from. Values are deliberately coarse — the goal is to reproduce the
*discriminating structure* of each technology (does the payload change between reads?
is there a challenge? how many authentication rounds?), not to simulate radio physics.

References for the intrinsic-weakness assignments are recorded against each weakness in
``mappings/protocol_weakness_control.yaml``.
"""

from __future__ import annotations

# cipher classes observable from protocol behaviour
CIPHER_NONE = 0
CIPHER_PROPRIETARY_BROKEN = 1
CIPHER_AES = 2

DEVICE_PROFILES: dict[str, dict] = {
    # ---------------- 125 kHz ----------------
    "EM4100/EM4102": {
        "protocol": "rfid_lf",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-MUTUAL-AUTH", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 40, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 40, "sak": 0, "response_us": 1400},
    },
    "HID Prox (H10301)": {
        "protocol": "rfid_lf",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-MUTUAL-AUTH", "W-NO-REVOCATION",
                      "W-SMALL-NAMESPACE"],
        "strength": "weak",
        "signal": {"bit_length": 26, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 24, "sak": 0, "response_us": 1600},
    },
    "Indala 26-bit": {
        "protocol": "rfid_lf",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-MUTUAL-AUTH", "W-NO-REVOCATION",
                      "W-SMALL-NAMESPACE"],
        "strength": "weak",
        "signal": {"bit_length": 26, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 24, "sak": 0, "response_us": 1750},
    },
    "T5577 (writable)": {
        "protocol": "rfid_lf",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-MUTUAL-AUTH", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 40, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 40, "sak": 0, "response_us": 1350},
    },
    # ---------------- 13.56 MHz ----------------
    "MIFARE Classic 1K/4K": {
        "protocol": "nfc_hf",
        "intrinsic": ["W-BROKEN-CRYPTO", "W-NO-MUTUAL-AUTH"],
        "strength": "legacy",
        "signal": {"bit_length": 32, "variable_bits": 8, "challenge": 1, "auth_rounds": 1,
                   "cipher": CIPHER_PROPRIETARY_BROKEN, "namespace_bits": 32, "sak": 8,
                   "response_us": 620},
    },
    "MIFARE Ultralight": {
        "protocol": "nfc_hf",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-MUTUAL-AUTH", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 56, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 56, "sak": 0, "response_us": 540},
    },
    "NTAG21x": {
        "protocol": "nfc_hf",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-MUTUAL-AUTH", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 56, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 56, "sak": 0, "response_us": 505},
    },
    "HID iCLASS legacy": {
        "protocol": "nfc_hf",
        "intrinsic": ["W-BROKEN-CRYPTO", "W-NO-MUTUAL-AUTH"],
        "strength": "legacy",
        "signal": {"bit_length": 64, "variable_bits": 8, "challenge": 1, "auth_rounds": 1,
                   "cipher": CIPHER_PROPRIETARY_BROKEN, "namespace_bits": 64, "sak": 32,
                   "response_us": 700},
    },
    "MIFARE DESFire EV2/EV3": {
        "protocol": "nfc_hf",
        "intrinsic": [],
        "strength": "strong",
        "signal": {"bit_length": 56, "variable_bits": 56, "challenge": 1, "auth_rounds": 3,
                   "cipher": CIPHER_AES, "namespace_bits": 56, "sak": 32, "response_us": 890},
    },
    "HID Seos": {
        "protocol": "nfc_hf",
        "intrinsic": [],
        "strength": "strong",
        "signal": {"bit_length": 64, "variable_bits": 64, "challenge": 1, "auth_rounds": 3,
                   "cipher": CIPHER_AES, "namespace_bits": 64, "sak": 32, "response_us": 960},
    },
    # ---------------- sub-GHz ----------------
    "Fixed-code OOK remote": {
        "protocol": "subghz",
        "intrinsic": ["W-FIXED-CODE-RF", "W-NO-CRYPTO", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 24, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 20, "sak": 0, "response_us": 0,
                   "counter_step": 0},
    },
    "KeeLoq rolling-code remote": {
        "protocol": "subghz",
        "intrinsic": ["W-BROKEN-CRYPTO", "W-ROLLING-REPLAY"],
        "strength": "legacy",
        "signal": {"bit_length": 66, "variable_bits": 32, "challenge": 0, "auth_rounds": 1,
                   "cipher": CIPHER_PROPRIETARY_BROKEN, "namespace_bits": 28, "sak": 0,
                   "response_us": 0, "counter_step": 1},
    },
    "AES rolling-code remote": {
        "protocol": "subghz",
        "intrinsic": ["W-ROLLING-REPLAY"],
        "strength": "strong",
        "signal": {"bit_length": 128, "variable_bits": 96, "challenge": 0, "auth_rounds": 2,
                   "cipher": CIPHER_AES, "namespace_bits": 64, "sak": 0, "response_us": 0,
                   "counter_step": 1},
    },
    # ---------------- infrared ----------------
    "IR barrier release": {
        "protocol": "ir",
        "intrinsic": ["W-IR-UNAUTH-CTRL", "W-NO-CRYPTO"],
        "strength": "weak",
        "signal": {"bit_length": 32, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 16, "sak": 0, "response_us": 0},
    },
    "IR device in secure area": {
        "protocol": "ir",
        "intrinsic": ["W-IR-UNAUTH-CTRL"],
        "strength": "weak",
        "signal": {"bit_length": 32, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 16, "sak": 0, "response_us": 0},
    },
    # ---------------- iButton / 1-Wire ----------------
    "DS1990A": {
        "protocol": "ibutton",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 64, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 48, "sak": 0, "response_us": 2200},
    },
    "Cyfral": {
        "protocol": "ibutton",
        "intrinsic": ["W-STATIC-ID", "W-NO-CRYPTO", "W-NO-REVOCATION"],
        "strength": "weak",
        "signal": {"bit_length": 16, "variable_bits": 0, "challenge": 0, "auth_rounds": 0,
                   "cipher": CIPHER_NONE, "namespace_bits": 16, "sak": 0, "response_us": 2600},
    },
}

# Convenience groupings used by the facility generator.
BY_PROTOCOL: dict[str, list[str]] = {}
for _name, _p in DEVICE_PROFILES.items():
    BY_PROTOCOL.setdefault(_p["protocol"], []).append(_name)

BY_STRENGTH: dict[str, list[str]] = {}
for _name, _p in DEVICE_PROFILES.items():
    BY_STRENGTH.setdefault(_p["strength"], []).append(_name)

DEVICE_TYPES = sorted(DEVICE_PROFILES)


# Some generations are not distinguishable from a passive read at all: a T5577 programmed
# with an EM4100 identifier *is* an EM4100 on the air, and an NTAG21x used UID-only
# presents like a MIFARE Ultralight. Reporting device accuracy without acknowledging this
# would understate the classifier; reporting only family accuracy would overstate it, so
# the evaluation reports both.
DEVICE_FAMILIES: dict[str, str] = {
    "EM4100/EM4102": "LF 40-bit static",
    "T5577 (writable)": "LF 40-bit static",
    "HID Prox (H10301)": "LF 26-bit Wiegand static",
    "Indala 26-bit": "LF 26-bit Wiegand static",
    "MIFARE Ultralight": "HF UID-only",
    "NTAG21x": "HF UID-only",
    "IR barrier release": "IR unauthenticated",
    "IR device in secure area": "IR unauthenticated",
    "MIFARE Classic 1K/4K": "HF Crypto1",
    "HID iCLASS legacy": "HF iCLASS legacy",
    "MIFARE DESFire EV2/EV3": "HF AES",
    "HID Seos": "HF AES",
    "Fixed-code OOK remote": "Sub-GHz fixed code",
    "KeeLoq rolling-code remote": "Sub-GHz KeeLoq",
    "AES rolling-code remote": "Sub-GHz AES rolling",
    "DS1990A": "1-Wire static",
    "Cyfral": "1-Wire static",
}


def device_family(device_type: str) -> str:
    """Return the identification family a generation belongs to."""
    return DEVICE_FAMILIES.get(device_type, device_type)
