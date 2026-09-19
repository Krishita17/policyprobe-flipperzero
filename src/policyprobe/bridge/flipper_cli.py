"""Hardware bridge: drives a real Flipper Zero over its USB serial CLI.

Scope note
----------
This backend issues **read and observe** commands only. It reads a credential that the
assessor is holding, or captures a transmission the assessor themselves triggers during
an authorised test. It contains no emulation, no writing to blank media, no brute
forcing and no jamming. Those capabilities exist in the Flipper firmware; PolicyProbe
does not orchestrate them, because a compliance assessment needs evidence that a
weakness exists, not a demonstration of entry. See ``docs/threat_model.md``.

Usage
-----
Connect the Flipper by USB, close the qFlipper desktop application (it holds the port),
then::

    policyprobe scan --backend flipper-cli --port /dev/tty.usbmodemflip_XXXX

Command names follow the Flipper CLI as exposed over serial. Firmware releases do move
these commands around; ``COMMANDS`` below is the single place to adjust them, and
``--dry-run`` prints what would be sent without opening the port.
"""

from __future__ import annotations

import random
import re
import time
from datetime import datetime, timezone

from ..schema import AccessPoint, Observation
from .base import Bridge

PROMPT = b">: "

# Read-only acquisition commands per protocol, in Flipper CLI syntax.
COMMANDS: dict[str, list[str]] = {
    "rfid_lf": ["rfid read"],
    "nfc_hf": ["nfc detect", "nfc read"],
    "subghz": ["subghz rx 433920000"],
    "ir": ["ir rx"],
    "ibutton": ["onewire search", "ibutton read"],
}

READ_TIMEOUT_S = 6.0
N_READS = 3


class FlipperCLIBridge(Bridge):
    """Serial CLI control of a Flipper Zero.

    Parameters
    ----------
    port:
        Serial device path, e.g. ``/dev/tty.usbmodemflip_Abcdefg`` or ``COM5``.
    dry_run:
        Print the command sequence instead of opening the port. Useful for reviewing
        exactly what the tool would do on a client site before doing it.
    """

    name = "flipper-cli"

    def __init__(self, port: str | None = None, baudrate: int = 230400,
                 dry_run: bool = False, timeout: float = READ_TIMEOUT_S):
        self.port = port
        self.baudrate = baudrate
        self.dry_run = dry_run
        self.timeout = timeout
        self._serial = None
        if not dry_run:
            self._open()

    # ------------------------------------------------------------------ connection --
    def _open(self) -> None:
        try:
            import serial   # pyserial
        except ImportError as exc:   # pragma: no cover - environment dependent
            raise RuntimeError(
                "pyserial is required for the flipper-cli backend: pip install pyserial"
            ) from exc
        if not self.port:
            raise ValueError("a serial --port is required for the flipper-cli backend")
        self._serial = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
        time.sleep(0.4)
        self._serial.reset_input_buffer()
        self._send("")           # wake the CLI and consume the banner

    def _send(self, command: str) -> str:
        """Send one CLI command and return everything received up to the next prompt."""
        if self.dry_run or self._serial is None:
            print(f"[dry-run] would send: {command!r}")
            return ""
        self._serial.write((command + "\r\n").encode())
        buf = b""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            chunk = self._serial.read(256)
            if chunk:
                buf += chunk
                if buf.rstrip().endswith(PROMPT.strip()):
                    break
            elif buf:
                break
        return buf.decode(errors="replace")

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None

    # -------------------------------------------------------------------- parsing --
    @staticmethod
    def parse_payload(protocol: str, transcript: str) -> dict:
        """Extract the fields the normalizer needs from a raw CLI transcript.

        Kept separate from I/O so it can be unit-tested against captured transcripts
        without hardware present.
        """
        payload: dict = {"raw": transcript}

        hexes = re.findall(r"\b(?:[0-9A-Fa-f]{2}[ :]){3,}[0-9A-Fa-f]{2}\b", transcript)
        payload["reads"] = [h.replace(" ", ":").upper() for h in hexes]
        payload["n_reads"] = len(payload["reads"])
        payload["distinct_reads"] = len(set(payload["reads"]))

        m = re.search(r"(\d+)\s*bits?", transcript, re.I)
        payload["bit_length"] = int(m.group(1)) if m else 0

        if protocol == "nfc_hf":
            m = re.search(r"SAK[:\s]+([0-9A-Fa-f]{2})", transcript)
            payload["sak"] = int(m.group(1), 16) if m else 0
            payload["challenge_observed"] = int(bool(re.search(r"auth", transcript, re.I)))
        else:
            payload["sak"] = 0
            payload["challenge_observed"] = 0

        m = re.search(r"[Cc]nt[:\s]+(\d+)", transcript)
        payload["counter_value"] = int(m.group(1)) if m else -1

        m = re.search(r"[Pp]rotocol[:\s]+([\w\- ]+)", transcript)
        payload["protocol_name"] = m.group(1).strip() if m else ""
        return payload

    # ---------------------------------------------------------------------- probe --
    def probe(self, access_point: AccessPoint) -> Observation:
        """Run the read-only command sequence for this access point's protocol."""
        commands = COMMANDS.get(access_point.protocol, [])
        transcripts: list[str] = []
        for _ in range(N_READS):
            for command in commands:
                transcripts.append(self._send(command))
            time.sleep(0.2)

        payload = self.parse_payload(access_point.protocol, "\n".join(transcripts))
        # Inventory attributes are recorded by the assessor, not read off the air.
        payload.update(
            reader_interface=access_point.reader_interface,
            credential_population=access_point.credential_population,
            legacy_format_probe=int(access_point.legacy_format_accepted),
            default_key_auth=-1,
            seq_first_diff_variance=-1.0,
            commands=commands,
        )
        return Observation(
            access_point_id=access_point.id,
            protocol=access_point.protocol,
            backend=self.name,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            payload=payload,
        )
