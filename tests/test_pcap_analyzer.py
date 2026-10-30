import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.pcap_analyzer import create_sample_pcap, parse_pcap

def test_create_and_parse_sample_pcap(tmp_path):
    """Verify that synthetic PCAP generation writes valid binary pcap headers and parses flows."""
    pcap_path = os.path.join(tmp_path, "test_sample.pcap")
    create_sample_pcap(pcap_path)
    
    assert os.path.exists(pcap_path)
    assert os.path.getsize(pcap_path) > 24 # Header is at least 24 bytes

    with open(pcap_path, "rb") as f:
        content = f.read()

    flows = parse_pcap(content)
    assert isinstance(flows, list)
    assert len(flows) > 0

    flow = flows[0]
    assert "source_ip" in flow
    assert "destination_ip" in flow
    assert "protocol" in flow
    assert "tot_fwd_pkts" in flow
    assert "totlen_fwd_pkts" in flow
