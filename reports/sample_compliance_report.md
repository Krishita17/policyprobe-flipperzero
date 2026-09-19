# Physical-Security Compliance Assessment — Meridian House

**Assessment date:** 2026-09-19  
**Sector:** Financial services  
**Access points assessed:** 28  
**Acquisition backend:** `mock`  
**Assessor:** Krishita Sanjay Choksi  
**Tool:** PolicyProbe v0.1.0

> This assessment covers the *technology layer* of physical access control: the
> credentials presented at each access point and the way each reader handles them.
> It does not cover construction, guarding, CCTV coverage or procedure, and it is
> not a substitute for a full physical-security assessment. Controls outside its
> reach are listed as *not assessed* and excluded from the posture score rather
> than being scored as passing.

## 1. Executive summary

Across 28 access points, PolicyProbe raised **115 findings**, of which **104** fail at least one control outright. Strict conformity is **ISO/IEC 27001 30.6%**, **NIST SP 800-53 17.4%**.

| Framework | Edition | Conformity | Estate score | Controls not met | Controls partially met | Coverage |
|---|---|---:|---:|---:|---:|---:|
| ISO/IEC 27001 | 2022 (Annex A; control set aligned to ISO/IEC 27002:2022) | **30.6%** | 66.6% | 11 | 3 | 94.7% |
| NIST SP 800-53 | Revision 5 (with updates through Release 5.1.1) | **17.4%** | 64.4% | 18 | 2 | 88.5% |

**Reading the two scores.** *Conformity* is the answer to the audit question: a
control is met only if it holds at every access point assessed, so one unreplaced
door fails it site-wide. *Estate score* is the answer to the management question:
it reports the share of access points at which each control actually holds. A
large gap between them means remediation is genuinely under way but not finished —
which conformity alone cannot show, because it stays flat until the last door is
done.

**Findings by risk rating:** 🟥 Critical 0 · 🟧 High 16 · 🟨 Medium 80 · 🟩 Low 19

## 2. Compliance posture by control family

### ISO/IEC 27001 — 2022 (Annex A; control set aligned to ISO/IEC 27002:2022)

| Control family | Conformity | Estate score |
|---|---:|---:|
| Organizational controls | 58.3% | 86.0% |
| Physical controls | 7.1% | 56.6% |
| Technological controls | 30.0% | 57.1% |

### NIST SP 800-53 — Revision 5 (with updates through Release 5.1.1)

| Control family | Conformity | Estate score |
|---|---:|---:|
| Access Control | 0.0% | 66.1% |
| Audit and Accountability | 25.0% | 59.8% |
| Assessment, Authorization, and Monitoring | 100.0% | 100.0% |
| Configuration Management | 0.0% | 76.8% |
| Identification and Authentication | 0.0% | 67.3% |
| Physical and Environmental Protection | 20.0% | 64.3% |
| Risk Assessment | 0.0% | 66.1% |
| System and Communications Protection | 0.0% | 33.0% |
| System and Information Integrity | 50.0% | 75.0% |

## 3. Control status detail

### ISO/IEC 27001

| Control | Title | Status | Access points failing | Estate score | Findings |
|---|---|---|---:|---:|---:|
| `A.5.15` | Access control | Partially met | 0 / 28 | 77% | 19 |
| `A.5.16` | Identity management | Not met | 8 / 28 | 70% | 25 |
| `A.5.17` | Authentication information | Met | 0 / 28 | 100% | 0 |
| `A.5.18` | Access rights | Not met | 8 / 28 | 70% | 9 |
| `A.5.35` | Independent review of information security | Met | 0 / 28 | 100% | 0 |
| `A.5.37` | Documented operating procedures | Met | 0 / 28 | 100% | 4 |
| `A.7.1` | Physical security perimeters | Not met | 1 / 28 | 96% | 1 |
| `A.7.12` | Cabling security | Not met | 17 / 28 | 39% | 17 |
| `A.7.13` | Equipment maintenance | Not met | 6 / 28 | 75% | 9 |
| `A.7.2` | Physical entry | Not met | 20 / 28 | 16% | 93 |
| `A.7.3` | Securing offices, rooms and facilities | Not met | 6 / 28 | 70% | 11 |
| `A.7.4` | Physical security monitoring | Not met | 22 / 28 | 12% | 47 |
| `A.7.9` | Security of assets off-premises | Partially met | 0 / 28 | 88% | 7 |
| `A.8.15` | Logging | Not met | 15 / 28 | 46% | 16 |
| `A.8.16` | Monitoring activities | Partially met | 0 / 28 | 61% | 29 |
| `A.8.34` | Protection of information systems during audit testing | Met | 0 / 28 | 100% | 0 |
| `A.8.5` | Secure authentication | Not met | 20 / 28 | 18% | 62 |
| `A.8.8` | Management of technical vulnerabilities | Not met | 11 / 28 | 61% | 34 |

### NIST SP 800-53

| Control | Title | Status | Access points failing | Estate score | Findings |
|---|---|---|---:|---:|---:|
| `AC-2` | Account Management | Not met | 8 / 28 | 70% | 18 |
| `AC-3` | Access Enforcement | Not met | 8 / 28 | 62% | 13 |
| `AU-2` | Event Logging | Not met | 15 / 28 | 46% | 15 |
| `AU-6` | Audit Record Review, Analysis, and Reporting | Partially met | 0 / 28 | 73% | 15 |
| `CA-8` | Penetration Testing | Met | 0 / 28 | 100% | 0 |
| `CM-6` | Configuration Settings | Not met | 4 / 28 | 77% | 13 |
| `IA-2` | Identification and Authentication (Organizational Users) | Not met | 6 / 28 | 66% | 23 |
| `IA-3` | Device Identification and Authentication | Not met | 9 / 28 | 64% | 24 |
| `IA-5` | Authenticator Management | Not met | 8 / 28 | 71% | 8 |
| `PE-16` | Delivery and Removal | Not met | 1 / 28 | 96% | 1 |
| `PE-18` | Location of System Components | Met | 0 / 28 | 100% | 5 |
| `PE-2` | Physical Access Authorizations | Not met | 8 / 28 | 70% | 16 |
| `PE-3` | Physical Access Control | Not met | 20 / 28 | 18% | 77 |
| `PE-3(1)` | Physical Access Control | System Access | Not met | 6 / 28 | 79% | 6 |
| `PE-3(5)` | Physical Access Control | Tamper Protection | Not met | 14 / 28 | 36% | 31 |
| `PE-4` | Access Control for Transmission | Not met | 17 / 28 | 39% | 17 |
| `PE-6` | Monitoring Physical Access | Not met | 15 / 28 | 34% | 32 |
| `PE-6(4)` | Monitoring Physical Access | Monitoring Physical Access to Systems | Met | 0 / 28 | 100% | 6 |
| `PE-8` | Visitor Access Records | Not met | 1 / 28 | 71% | 16 |
| `RA-5` | Vulnerability Monitoring and Scanning | Not met | 8 / 28 | 66% | 20 |
| `SC-13` | Cryptographic Protection | Not met | 12 / 28 | 48% | 17 |
| `SC-8` | Transmission Confidentiality and Integrity | Not met | 20 / 28 | 18% | 42 |
| `SI-4` | System Monitoring | Partially met | 0 / 28 | 75% | 14 |

## 4. Gap list with evidence

Each gap below is a finding that fails at least one control. The evidence column
is what was actually observed at the access point; the controls column names the
controls that finding provides evidence against.

| Risk | Access point | Zone | Protocol | Weakness | Evidence | Controls failed |
|---|---|---|---|---|---|---|
| 🟧 High | Loading bay roller door 2 | restricted | `subghz` | Deprecated or academically broken proprietary cipher | Identified as KeeLoq rolling-code remote (confidence 1.00). This generation's proprietary cipher has published practical key-recovery attacks (see mapping references). | `A.8.5, A.8.8, RA-5, SC-13` |
| 🟧 High | Loading bay roller door 2 | restricted | `subghz` | Single-factor possession-only credential at a high-sensitivity boundary | A single possession factor is enforced at a restricted zone boundary; no PIN, biometric or supervised entry is required. | `A.7.3, A.8.5, IA-2, PE-3(1)` |
| 🟧 High | Server room 2 | secure | `nfc_hf` | Reader accepts a legacy insecure format alongside the secure format | Identified as MIFARE DESFire EV2/EV3 (confidence 0.92). A legacy-format credential was accepted by this reader alongside the current format. | `A.7.2, A.8.5, A.8.8, CM-6, PE-3` |
| 🟧 High | Server room 2 | secure | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟧 High | Server room 2 | secure | `nfc_hf` | Single-factor possession-only credential at a high-sensitivity boundary | A single possession factor is enforced at a secure zone boundary; no PIN, biometric or supervised entry is required. | `A.7.3, A.8.5, IA-2, PE-3(1)` |
| 🟧 High | Server room 3 | secure | `nfc_hf` | Reader accepts a legacy insecure format alongside the secure format | Identified as MIFARE DESFire EV2/EV3 (confidence 0.97). A legacy-format credential was accepted by this reader alongside the current format. | `A.7.2, A.8.5, A.8.8, CM-6, PE-3` |
| 🟧 High | Server room 3 | secure | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟧 High | Server room 3 | secure | `nfc_hf` | Single-factor possession-only credential at a high-sensitivity boundary | A single possession factor is enforced at a secure zone boundary; no PIN, biometric or supervised entry is required. | `A.7.3, A.8.5, IA-2, PE-3(1)` |
| 🟧 High | Loading bay roller door 1 | restricted | `subghz` | Deprecated or academically broken proprietary cipher | Identified as KeeLoq rolling-code remote (confidence 1.00). This generation's proprietary cipher has published practical key-recovery attacks (see mapping references). | `A.8.5, A.8.8, RA-5, SC-13` |
| 🟧 High | Loading bay roller door 1 | restricted | `subghz` | Single-factor possession-only credential at a high-sensitivity boundary | A single possession factor is enforced at a restricted zone boundary; no PIN, biometric or supervised entry is required. | `A.7.3, A.8.5, IA-2, PE-3(1)` |
| 🟧 High | Loading bay roller door 3 | restricted | `subghz` | Fixed-code sub-GHz transmitter (no rolling code) | Identified as Fixed-code OOK remote (confidence 1.00). Counter step observed as 0: the remote transmits an identical code on every press. | `A.7.1, A.7.2, A.8.5, AC-3, PE-16, PE-3, SC-8` |
| 🟧 High | Loading bay roller door 3 | restricted | `subghz` | No cryptographic authentication in the credential exchange | Identified as Fixed-code OOK remote (confidence 1.00). No challenge and no authentication round observed in the exchange. | `A.7.2, A.8.5, IA-3, PE-3, SC-13, SC-8` |
| 🟧 High | Loading bay roller door 3 | restricted | `subghz` | Single-factor possession-only credential at a high-sensitivity boundary | A single possession factor is enforced at a restricted zone boundary; no PIN, biometric or supervised entry is required. | `A.7.3, A.8.5, IA-2, PE-3(1)` |
| 🟧 High | Server room 5 | secure | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟧 High | Plant room 1 | restricted | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟧 High | Plant room 1 | restricted | `nfc_hf` | Single-factor possession-only credential at a high-sensitivity boundary | A single possession factor is enforced at a restricted zone boundary; no PIN, biometric or supervised entry is required. | `A.7.3, A.8.5, IA-2, PE-3(1)` |
| 🟨 Medium | Loading bay roller door 2 | restricted | `subghz` | Access point produces no retained access event record | Access point is not integrated with the access control platform; no retained event is produced for entries through it. | `A.7.4, A.8.15, AU-2, PE-6` |
| 🟨 Medium | Server room 2 | secure | `nfc_hf` | Reader has no tamper detection or no reporting path for tamper events | No supervised tamper switch on the reader assembly at this access point. | `A.7.4, PE-3(5)` |
| 🟨 Medium | Server room 2 | secure | `nfc_hf` | Access point produces no retained access event record | Access point is not integrated with the access control platform; no retained event is produced for entries through it. | `A.7.4, A.8.15, AU-2, PE-6` |
| 🟨 Medium | Server room 3 | secure | `nfc_hf` | Reader has no tamper detection or no reporting path for tamper events | No supervised tamper switch on the reader assembly at this access point. | `A.7.4, PE-3(5)` |
| 🟨 Medium | Staff entrance 1 | general | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟨 Medium | Main entrance turnstile 3 | general | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟨 Medium | Data hall door 1 | secure | `nfc_hf` | No cryptographic authentication in the credential exchange | Identified as MIFARE Ultralight (confidence 0.57). No challenge and no authentication round observed in the exchange. | `A.7.2, A.8.5, IA-3, PE-3, SC-13, SC-8` |
| 🟨 Medium | Data hall door 1 | secure | `nfc_hf` | Sequential or low-entropy identifier allocation | Identified as MIFARE Ultralight (confidence 0.57). Identifiers sampled from the same issuing batch differ by a near-constant step, indicating sequential allocation. | `A.5.16, A.7.2, AC-2, PE-2, PE-3` |
| 🟨 Medium | Data hall door 1 | secure | `nfc_hf` | Static, non-authenticating credential identifier | Identified as MIFARE Ultralight (confidence 0.57). 3 repeat reads returned 1 distinct payload(s); the credential presents a fixed identifier with no challenge. | `A.7.2, A.8.5, AC-3, IA-3, PE-3` |
| 🟨 Medium | Data hall door 1 | secure | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as OSDP with Secure Channel not enabled, which leaves the link unauthenticated. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟨 Medium | Server room 1 | secure | `nfc_hf` | No cryptographic authentication in the credential exchange | Identified as MIFARE Ultralight (confidence 0.86). No challenge and no authentication round observed in the exchange. | `A.7.2, A.8.5, IA-3, PE-3, SC-13, SC-8` |
| 🟨 Medium | Server room 1 | secure | `nfc_hf` | Sequential or low-entropy identifier allocation | Identified as MIFARE Ultralight (confidence 0.86). Identifiers sampled from the same issuing batch differ by a near-constant step, indicating sequential allocation. | `A.5.16, A.7.2, AC-2, PE-2, PE-3` |
| 🟨 Medium | Server room 1 | secure | `nfc_hf` | Static, non-authenticating credential identifier | Identified as MIFARE Ultralight (confidence 0.86). 3 repeat reads returned 1 distinct payload(s); the credential presents a fixed identifier with no challenge. | `A.7.2, A.8.5, AC-3, IA-3, PE-3` |
| 🟨 Medium | Server room 1 | secure | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟨 Medium | Server room 6 | secure | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |
| 🟨 Medium | Comms room 1 | secure | `ir` | Security-relevant device controllable by unauthenticated infrared command | Identified as IR device in secure area (confidence 0.86). The device acted on a replayed capture of its own infrared command with no authentication. | `A.8.5` |
| 🟨 Medium | Comms room 1 | secure | `ir` | Access point produces no retained access event record | Access point is not integrated with the access control platform; no retained event is produced for entries through it. | `A.7.4, A.8.15, AU-2, PE-6` |
| 🟨 Medium | Plant room 1 | restricted | `nfc_hf` | Reader accepts a legacy insecure format alongside the secure format | Identified as MIFARE DESFire EV2/EV3 (confidence 0.61). A legacy-format credential was accepted by this reader alongside the current format. | `A.7.2, A.8.5, A.8.8, CM-6, PE-3` |
| 🟨 Medium | Loading bay roller door 1 | restricted | `subghz` | Access point produces no retained access event record | Access point is not integrated with the access control platform; no retained event is produced for entries through it. | `A.7.4, A.8.15, AU-2, PE-6` |
| 🟨 Medium | Loading bay roller door 3 | restricted | `subghz` | Reader has no tamper detection or no reporting path for tamper events | No supervised tamper switch on the reader assembly at this access point. | `A.7.4, PE-3(5)` |
| 🟨 Medium | Loading bay roller door 3 | restricted | `subghz` | Access point produces no retained access event record | Access point is not integrated with the access control platform; no retained event is produced for entries through it. | `A.7.4, A.8.15, AU-2, PE-6` |
| 🟨 Medium | Loading bay roller door 3 | restricted | `subghz` | Credential cannot be expired or revoked at the credential layer | Fixed-code OOK remote carries no expiry field and nothing cryptographically revocable; revocation depends entirely on the controller allow list. | `A.5.18, IA-5, PE-2` |
| 🟨 Medium | Main entrance turnstile 1 | general | `nfc_hf` | Reader accepts a legacy insecure format alongside the secure format | Identified as MIFARE DESFire EV2/EV3 (confidence 0.99). A legacy-format credential was accepted by this reader alongside the current format. | `A.7.2, A.8.5, A.8.8, CM-6, PE-3` |
| 🟨 Medium | Main entrance turnstile 1 | general | `nfc_hf` | Credential data traverses reader-to-controller wiring unauthenticated | Reader-to-controller interface recorded as Wiegand: the decoded credential crosses the reader's wiring unauthenticated and in the clear. | `A.7.12, A.7.2, PE-3, PE-4, SC-8` |

*64 further gaps are listed in `results/findings.csv`.*

## 5. Remediation roadmap

Ranked by priority band, then by the total risk sitting behind each gap.

| Priority | Gap | Access points | Zones | Effort | Controls failed | Recommended action |
|---|---|---:|---|---|---|---|
| **P1** | Credential data traverses reader-to-controller wiring unauthenticated | 17 | general, restricted, secure | Medium | `A.7.12, A.7.2, PE-3, PE-4, SC-8` | Migrate reader-to-controller communications to OSDP with Secure Channel enabled, and enforce reader tamper reporting. |
| **P1** | No cryptographic authentication in the credential exchange | 10 | general, restricted, secure | High | `A.7.2, A.8.5, IA-3, PE-3, SC-13, SC-8` | Replace the technology at security-relevant boundaries; where replacement is deferred, add an independent factor that is not carried on the same channel. |
| **P1** | Single-factor possession-only credential at a high-sensitivity boundary | 6 | restricted, secure | Medium | `A.7.3, A.8.5, IA-2, PE-3(1)` | Require a second factor at Restricted and Secure boundaries — PIN, biometric, or supervised entry. |
| **P1** | Sequential or low-entropy identifier allocation | 7 | general, secure | Medium | `A.5.16, A.7.2, AC-2, PE-2, PE-3` | Re-issue with randomly allocated identifiers from the full available namespace, and rate-limit or alarm on repeated rejected reads. |
| **P1** | Static, non-authenticating credential identifier | 7 | general, secure | High | `A.7.2, A.8.5, AC-3, IA-3, PE-3` | Migrate to a credential that performs mutual cryptographic authentication; treat legacy IDs as identifiers only, never as authenticators. |
| **P1** | Reader accepts a legacy insecure format alongside the secure format | 4 | general, restricted, secure | Low | `A.7.2, A.8.5, A.8.8, CM-6, PE-3` | Complete the migration: disable legacy format acceptance reader by reader and evidence the date each was cut over. |
| **P1** | Deprecated or academically broken proprietary cipher | 3 | general, restricted | Medium | `A.8.5, A.8.8, RA-5, SC-13` | Cut over to the vendor's current secure generation and disable the broken generation at the reader. |
| **P1** | Fixed-code sub-GHz transmitter (no rolling code) | 1 | restricted | Medium | `A.7.1, A.7.2, A.8.5, AC-3, PE-16, PE-3, SC-8` | Replace fixed-code receivers with authenticated rolling-code or credentialled access; log every gate operation to the access control platform. |
| **P2** | Access point produces no retained access event record | 15 | general, restricted, secure | Medium | `A.7.4, A.8.15, AU-2, PE-6` | Integrate standalone access points into the access control platform, or compensate with monitored video and documented risk acceptance. |
| **P2** | Reader has no tamper detection or no reporting path for tamper events | 14 | general, restricted, secure | Low | `A.7.4, PE-3(5)` | Enable and supervise tamper switches on every reader and receiver; alarm tamper to a monitored destination. |
| **P2** | Credential cannot be expired or revoked at the credential layer | 8 | general, restricted, secure | Medium | `A.5.18, IA-5, PE-2` | Adopt credentials supporting expiry and cryptographic revocation; verify leaver revocation end to end, including standalone points. |
| **P2** | Reader is not authenticated to the credential | 7 | general, secure | Low | `-` | Require mutual authentication and add shielding for high-sensitivity holders. |
| **P2** | End-of-life credential or reader generation with no vendor security maintenance | 6 | general, secure | High | `A.7.13, A.8.8, RA-5` | Put the estate on a dated refresh plan; do not extend unsupported generations into new zones. |
| **P2** | Rolling code defeatable by jam-and-replay or counter desynchronisation | 2 | restricted | Medium | `-` | Prefer receivers with challenge-response or AES-based bidirectional authentication; monitor gate events for out-of-sequence opens. |
| **P2** | Identifier namespace too small for the credential population | 2 | general | Medium | `-` | Move to a large-namespace, site-unique credential format and retire shared facility codes. |
| **P2** | Non-attributable shared or pooled credential in use | 1 | restricted | Low | `A.5.16, AC-2, IA-2, PE-8` | Issue individually attributable credentials including to contractors and visitors; retire pooled credentials. |
| **P3** | Security-relevant device controllable by unauthenticated infrared command | 5 | general, secure | Low | `A.8.5` | Remove IR control from security-relevant actuators; where the device must keep IR, block line of sight from outside the boundary. |

## 6. Coverage and limitations

**ISO/IEC 27001:** 18 of 19 catalogued controls were assessed (94.7%). 1 could not be assessed by this method and are excluded from the posture score:

- `A.7.6` Working in secure areas — Out of scope: behavioural and procedural control.

**NIST SP 800-53:** 23 of 26 catalogued controls were assessed (88.5%). 3 could not be assessed by this method and are excluded from the posture score:

- `PE-20` Asset Monitoring and Tracking — Out of scope.
- `PE-5` Access Control for Output Devices — Out of scope for credential probing.
- `PE-6(1)` Monitoring Physical Access | Intrusion Alarms and Surveillance Equipment — Requires site survey of alarm and camera coverage; outside the probe's data.

Further limitations:

- Findings rest on the credential technology observed at the time of the visit;
  an estate mid-migration can present differently a month later.
- Low-confidence classifications are reported at reduced weight and are not
  permitted to fail a control on their own. Their confidence is recorded in
  `results/findings.csv`.
- Where a test could not be run on site (no legacy specimen to present, no safe
  window for a default-key attempt), the result is recorded as unknown, never as
  a pass.

---

Generated by PolicyProbe v0.1.0 · Krishita Sanjay Choksi · 2026-09-19