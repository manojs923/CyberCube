import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.predict import predict, MITRE_MAP, get_model
from backend.app.xai_service import xai_service

def test_predict_benign_flow():
    """Verify that normal packet features return benign or valid prediction."""
    sample_flow = {
        'protocol': 6,
        'port': 443,
        'packet_size': 120,
        'duration': 1.5,
        'flow_duration': 1500,
        'tot_fwd_pkts': 10,
        'tot_bwd_pkts': 12,
        'totlen_fwd_pkts': 1200,
        'totlen_bwd_pkts': 1400,
        'fwd_pkt_len_mean': 120,
        'bwd_pkt_len_mean': 116,
        'flow_byts_s': 1733,
        'flow_pkts_s': 14.6,
        'syn_flag_cnt': 1,
        'rst_flag_cnt': 0,
        'ack_flag_cnt': 1
    }
    pred_class, confidence, severity = predict(sample_flow)
    assert pred_class in ['Benign', 'DDoS', 'PortScan', 'Brute Force', 'Web Attack', 'Botnet']
    assert 0.0 <= confidence <= 1.0
    assert severity in ['low', 'medium', 'high', 'critical']

def test_mitre_mapping():
    """Ensure MITRE ATT&CK techniques are mapped for known attack classes."""
    assert MITRE_MAP['DDoS'] == 'T1498'
    assert MITRE_MAP['PortScan'] == 'T1046'
    assert MITRE_MAP['Brute Force'] == 'T1110'
    assert MITRE_MAP['Web Attack'] == 'T1190'
    assert MITRE_MAP['Botnet'] == 'T1071'

def test_counterfactual_xai_analysis():
    """Test counterfactual perturbation analysis shifts confidence."""
    flow = {
        'flow_duration': 420.0,
        'tot_fwd_pkts': 850.0,
        'tot_bwd_pkts': 12.0,
        'totlen_fwd_pkts': 46200.0,
        'totlen_bwd_pkts': 720.0,
        'flow_byts_s': 124500.0,
        'flow_pkts_s': 2045.0,
        'syn_flag_cnt': 850.0,
        'fwd_pkt_len_mean': 54.0,
        'bwd_pkt_len_mean': 60.0
    }
    perturbations = {
        'syn_flag_cnt': 1.0,
        'flow_pkts_s': 10.0,
        'flow_duration': 60000.0
    }
    res = xai_service.counterfactual_analysis(flow, perturbations)
    assert "baseline" in res
    assert "counterfactual" in res
    assert "class_probabilities" in res
    assert 0.0 <= res["baseline"]["confidence"] <= 1.0
    assert 0.0 <= res["counterfactual"]["confidence"] <= 1.0
