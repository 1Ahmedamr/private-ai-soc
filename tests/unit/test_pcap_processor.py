# tests/unit/test_pcap_processor.py

import pytest
from unittest.mock import patch
from src.pipeline.pcap_processor import process_pcap

pytestmark = pytest.mark.skipif(
    True, reason="Requires real zeek/suricata binaries + a real pcap - run manually, not in CI"
)


def test_placeholder_marks_this_suite_as_manual_only():
    """
    Why skip entirely rather than mock subprocess.run? Mocking subprocess
    output for Zeek/Suricata would test our OWN glue code only, giving
    false confidence that real binary integration works. Since CI
    (GitHub Actions) doesn't have Zeek/Suricata installed, this suite is
    explicitly marked manual-only rather than faked with mocks that
    wouldn't catch a real integration break.
    """
    pass