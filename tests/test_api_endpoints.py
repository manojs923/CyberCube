import os
import sys
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from backend.app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_threats_summary():
    headers = {"X-Tenant-Key": "test_tenant_key_1"}
    response = client.get("/threats/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "critical" in data
    assert "high" in data
    assert "blocked" in data

def test_simulate_attack_and_rollback():
    """Verify Red Team attack simulation, containment block, and rollback."""
    headers = {"X-Tenant-Key": "test_tenant_sim"}
    
    # 1. Trigger simulated attack
    res_sim = client.post("/simulate/attack?vector=ddos", headers=headers)
    assert res_sim.status_code == 200
    threat = res_sim.json()
    threat_id = threat["id"]
    assert threat["attack_type"] == "DDoS"
    assert threat["severity"] == "critical"

    # 2. Block the attacker
    res_block = client.post(f"/threats/{threat_id}/block?enforce_os=false", headers=headers)
    assert res_block.status_code == 200
    assert res_block.json()["is_blocked"] is True

    # 3. Rollback the quarantine (Unblock)
    res_unblock = client.post(f"/threats/{threat_id}/unblock", headers=headers)
    assert res_unblock.status_code == 200
    assert res_unblock.json()["is_blocked"] is False
    assert res_unblock.json()["status"] == "open"

def test_cryptographic_audit_verification():
    """Verify cryptographic hash chain calculation across logs."""
    headers = {"X-Tenant-Key": "test_tenant_sim"}
    response = client.get("/audit/verify", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SECURE_VERIFIED"
    assert "chain_head" in data
    assert data["is_tamper_free"] is True
