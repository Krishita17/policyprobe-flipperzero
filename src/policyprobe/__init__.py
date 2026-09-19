"""PolicyProbe — a Flipper-driven physical-security compliance scanner mapped to control frameworks.

The package is organised as a pipeline:

    bridge      acquire observations from access points (mock or real Flipper Zero)
    normalize   flatten protocol-specific observations into one finding schema
    classify    identify device type and flag weak credential implementations
    score       rate each finding by weakness severity and exposure
    mapping     map each finding onto ISO/IEC 27001:2022 and NIST SP 800-53 Rev. 5 controls
    report      roll findings up into a compliance posture, gap list and remediation roadmap

Author: Krishita Sanjay Choksi
"""

__version__ = "0.1.0"
__author__ = "Krishita Sanjay Choksi"
__license__ = "MIT"
