"""Cytadel Exposure Assessment — authorized defensive breach-notification tool.

Design invariant: plaintext credentials never leave ``parser.py``. Everything that
flows to search, reporting, the UI, or exports carries only non-reversible
redaction signals (see ``redact.py``). This is what keeps the tool lawful under
GDPR data-minimization and safe to hand to a client.
"""

__version__ = "1.0.2"
