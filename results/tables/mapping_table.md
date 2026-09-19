| Protocol | Weakness | Sev. | Detected by | ISO/IEC 27001:2022 controls failed | NIST SP 800-53 Rev. 5 controls failed |
|---|---|---|---|---|---|
| 125 kHz · 13.56 MHz · 1-Wire | **Static, non-authenticating credential identifier**<br/>`W-STATIC-ID` | High | RF probe | `A.7.2`, `A.8.5` | `PE-3`, `IA-3`, `AC-3` |
| 125 kHz · 13.56 MHz · 1-Wire · Sub-GHz · IR | **No cryptographic authentication in the credential exchange**<br/>`W-NO-CRYPTO` | High | RF probe | `A.8.5`, `A.7.2` | `SC-13`, `SC-8`, `PE-3`, `IA-3` |
| 13.56 MHz · Sub-GHz | **Deprecated or academically broken proprietary cipher**<br/>`W-BROKEN-CRYPTO` | High | RF probe | `A.8.5`, `A.8.8` | `SC-13`, `RA-5` |
| 13.56 MHz | **Factory-default or publicly published sector keys in use**<br/>`W-DEFAULT-KEYS` | Critical | RF probe | `A.5.17`, `A.8.5`, `A.7.2`, `A.8.8` | `IA-5`, `CM-6`, `PE-3` |
| Sub-GHz | **Fixed-code sub-GHz transmitter (no rolling code)**<br/>`W-FIXED-CODE-RF` | High | RF probe | `A.7.2`, `A.7.1`, `A.8.5` | `PE-3`, `PE-16`, `SC-8`, `AC-3` |
| Sub-GHz | **Rolling code defeatable by jam-and-replay or counter desynchronisation**<br/>`W-ROLLING-REPLAY` | Medium | RF probe | — | — |
| 125 kHz · 13.56 MHz · 1-Wire | **Sequential or low-entropy identifier allocation**<br/>`W-SEQUENTIAL-ID` | High | RF probe | `A.5.16`, `A.7.2` | `PE-2`, `AC-2`, `PE-3` |
| 125 kHz · 13.56 MHz | **Identifier namespace too small for the credential population**<br/>`W-SMALL-NAMESPACE` | Medium | RF probe | — | — |
| 13.56 MHz · 125 kHz | **Reader is not authenticated to the credential**<br/>`W-NO-MUTUAL-AUTH` | Medium | RF probe | — | — |
| 125 kHz · 13.56 MHz | **Credential data traverses reader-to-controller wiring unauthenticated**<br/>`W-WIRE-CLEARTEXT` | High | Inventory | `A.7.12`, `A.7.2` | `PE-4`, `SC-8`, `PE-3` |
| 125 kHz · 13.56 MHz · Sub-GHz · IR · 1-Wire | **Reader has no tamper detection or no reporting path for tamper events**<br/>`W-NO-TAMPER` | Medium | Inventory | `A.7.4` | `PE-3(5)` |
| 125 kHz · 13.56 MHz · Sub-GHz · IR · 1-Wire | **Access point produces no retained access event record**<br/>`W-NO-EVENT-LOG` | Medium | Inventory | `A.8.15`, `A.7.4` | `AU-2`, `PE-6` |
| 125 kHz · 13.56 MHz · 1-Wire · Sub-GHz | **Credential cannot be expired or revoked at the credential layer**<br/>`W-NO-REVOCATION` | Medium | Inventory | `A.5.18` | `PE-2`, `IA-5` |
| 125 kHz · 13.56 MHz · Sub-GHz · 1-Wire | **Non-attributable shared or pooled credential in use**<br/>`W-SHARED-CREDENTIAL` | Medium | Inventory | `A.5.16` | `AC-2`, `IA-2`, `PE-8` |
| 125 kHz · 13.56 MHz · Sub-GHz · 1-Wire | **Single-factor possession-only credential at a high-sensitivity boundary**<br/>`W-SINGLE-FACTOR-HIGH` | High | Inventory | `A.8.5`, `A.7.3` | `IA-2`, `PE-3(1)` |
| IR | **Security-relevant device controllable by unauthenticated infrared command**<br/>`W-IR-UNAUTH-CTRL` | Medium | RF probe | `A.8.5` | — |
| 125 kHz · 13.56 MHz · 1-Wire | **End-of-life credential or reader generation with no vendor security maintenance**<br/>`W-LEGACY-EOL` | Medium | Inventory | `A.7.13`, `A.8.8` | `RA-5` |
| 13.56 MHz · 125 kHz | **Reader accepts a legacy insecure format alongside the secure format**<br/>`W-MIXED-MODE` | High | RF probe | `A.8.5`, `A.7.2`, `A.8.8` | `CM-6`, `PE-3` |
