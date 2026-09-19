| Weakness | Protocols | ISO/IEC 27001:2022 | NIST SP 800-53 Rev. 5 |
|---|---|---|---|
| Static, non-authenticating credential identifier<br/>`W-STATIC-ID` | rfid_lf, nfc_hf, ibutton | `A.7.2*`, `A.8.5*`, `A.5.16`, `A.8.8` | `PE-3*`, `IA-3*`, `AC-3*`, `IA-2`, `RA-5` |
| No cryptographic authentication in the credential exchange<br/>`W-NO-CRYPTO` | rfid_lf, nfc_hf, ibutton, subghz, ir | `A.8.5*`, `A.7.2*`, `A.8.8` | `SC-13*`, `SC-8*`, `PE-3*`, `IA-3*` |
| Deprecated or academically broken proprietary cipher<br/>`W-BROKEN-CRYPTO` | nfc_hf, subghz | `A.8.5*`, `A.8.8*`, `A.7.13`, `A.7.2` | `SC-13*`, `PE-3`, `RA-5*`, `CM-6` |
| Factory-default or publicly published sector keys in use<br/>`W-DEFAULT-KEYS` | nfc_hf | `A.5.17*`, `A.8.5*`, `A.7.2*`, `A.8.8*` | `IA-5*`, `CM-6*`, `PE-3*`, `SC-13` |
| Fixed-code sub-GHz transmitter (no rolling code)<br/>`W-FIXED-CODE-RF` | subghz | `A.7.2*`, `A.7.1*`, `A.8.5*`, `A.7.4` | `PE-3*`, `PE-16*`, `SC-8*`, `AC-3*`, `PE-6` |
| Rolling code defeatable by jam-and-replay or counter desynchronisation<br/>`W-ROLLING-REPLAY` | subghz | `A.7.2`, `A.8.5`, `A.8.8` | `PE-3`, `SC-8`, `PE-6` |
| Sequential or low-entropy identifier allocation<br/>`W-SEQUENTIAL-ID` | rfid_lf, nfc_hf, ibutton | `A.5.16*`, `A.7.2*`, `A.5.15` | `PE-2*`, `AC-2*`, `PE-3*`, `IA-2` |
| Identifier namespace too small for the credential population<br/>`W-SMALL-NAMESPACE` | rfid_lf, nfc_hf | `A.5.16`, `A.7.2`, `A.8.8` | `IA-2`, `AC-2`, `PE-3` |
| Reader is not authenticated to the credential<br/>`W-NO-MUTUAL-AUTH` | nfc_hf, rfid_lf | `A.8.5`, `A.7.9`, `A.7.2` | `IA-3`, `SC-8`, `PE-3` |
| Credential data traverses reader-to-controller wiring unauthenticated<br/>`W-WIRE-CLEARTEXT` | rfid_lf, nfc_hf | `A.7.12*`, `A.7.2*`, `A.8.5`, `A.7.4` | `PE-4*`, `SC-8*`, `PE-3*`, `PE-3(5)` |
| Reader has no tamper detection or no reporting path for tamper events<br/>`W-NO-TAMPER` | rfid_lf, nfc_hf, subghz, ir, ibutton | `A.7.4*`, `A.7.2`, `A.8.16` | `PE-3(5)*`, `PE-6`, `SI-4` |
| Access point produces no retained access event record<br/>`W-NO-EVENT-LOG` | rfid_lf, nfc_hf, subghz, ir, ibutton | `A.8.15*`, `A.7.4*`, `A.8.16` | `AU-2*`, `PE-6*`, `PE-8`, `AU-6` |
| Credential cannot be expired or revoked at the credential layer<br/>`W-NO-REVOCATION` | rfid_lf, nfc_hf, ibutton, subghz | `A.5.18*`, `A.5.16`, `A.7.2` | `PE-2*`, `IA-5*`, `AC-2` |
| Non-attributable shared or pooled credential in use<br/>`W-SHARED-CREDENTIAL` | rfid_lf, nfc_hf, subghz, ibutton | `A.5.16*`, `A.5.18`, `A.8.15` | `AC-2*`, `IA-2*`, `PE-2`, `PE-8*` |
| Single-factor possession-only credential at a high-sensitivity boundary<br/>`W-SINGLE-FACTOR-HIGH` | rfid_lf, nfc_hf, subghz, ibutton | `A.8.5*`, `A.7.3*`, `A.7.2`, `A.5.15` | `IA-2*`, `PE-3(1)*`, `PE-3`, `PE-6(4)` |
| Security-relevant device controllable by unauthenticated infrared command<br/>`W-IR-UNAUTH-CTRL` | ir | `A.7.2`, `A.7.3`, `A.8.5*` | `PE-3`, `AC-3`, `SC-8`, `PE-18` |
| End-of-life credential or reader generation with no vendor security maintenance<br/>`W-LEGACY-EOL` | rfid_lf, nfc_hf, ibutton | `A.7.13*`, `A.8.8*`, `A.5.15` | `RA-5*`, `CM-6`, `PE-3` |
| Reader accepts a legacy insecure format alongside the secure format<br/>`W-MIXED-MODE` | nfc_hf, rfid_lf | `A.8.5*`, `A.7.2*`, `A.8.8*`, `A.5.37` | `CM-6*`, `PE-3*`, `SC-13`, `RA-5` |

`*` marks a control the weakness fails outright; the rest are controls it weakens or provides supporting evidence against.
