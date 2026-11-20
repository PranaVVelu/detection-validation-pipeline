"""Response drafts must wait for a person, and an approved action must really take effect."""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

import pytest
import yaml

from conftest import REPO_ROOT, run_script

SHARING = REPO_ROOT / "detections/sigma/license/license_activation_key_sharing.yml"
ENCODED = REPO_ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command.yml"
TOKEN = "test-admin-token"


def draft(rule, tmp_path):
    events, alerts, out = tmp_path / "events.jsonl", tmp_path / "alerts.json", tmp_path / "incidents.json"
    assert run_script("simulate_atomic.py", "--rule", rule, "--run-id", "r", "--out", events).returncode == 0
    assert run_script("ship_events.py", "--rule", rule, "--events", events, "--run-id", "r", "--alerts-out", alerts).returncode == 0
    result = run_script("respond.py", "draft", "--rule", rule, "--alerts-file", alerts, "--run-id", "r", "--out", out)
    assert result.returncode == 0, result.stdout + result.stderr
    return out, json.loads(out.read_text(encoding="utf-8"))["incidents"]


@pytest.fixture
def license_server(tmp_path):
    env = {**os.environ, "LICENSE_ADMIN_TOKEN": TOKEN}
    server = subprocess.Popen([sys.executable, str(REPO_ROOT / "game/license_server.py"), "--log", str(tmp_path / "log.jsonl")],
                              stdout=subprocess.PIPE, text=True, env=env)
    try:
        yield server.stdout.readline().strip()
    finally:
        server.terminate()
        server.wait(timeout=10)


def activate(url, key, machine):
    request = urllib.request.Request(f"{url}/activate", data=json.dumps({"key": key, "machine_id": machine}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        return json.load(exc)


def approve(incidents, incident_id, url, token=TOKEN):
    env = {**os.environ, "LICENSE_ADMIN_TOKEN": token}
    return subprocess.run([sys.executable, str(REPO_ROOT / "scripts/respond.py"), "approve", "--incidents", str(incidents),
                           "--id", incident_id, "--approver", "Pranav", "--license-url", url],
                          capture_output=True, text=True, env=env, timeout=60)


def test_every_rule_has_a_playbook():
    playbooks = yaml.safe_load((REPO_ROOT / "response/playbooks.yml").read_text(encoding="utf-8"))["playbooks"]
    rules = {p.relative_to(REPO_ROOT).as_posix() for p in (REPO_ROOT / "detections").rglob("*") if p.suffix in {".yml", ".kql"}}
    assert set(playbooks) == rules


def test_draft_waits_for_approval_and_includes_what_the_rule_is_known_to_miss(tmp_path):
    _, incidents = draft(SHARING, tmp_path)
    incident = incidents[0]
    assert incident["action"]["status"] == "awaiting approval" and incident["approval"] is None
    assert incident["action"]["target_value"] == "shared-key"
    assert any("same machine ID" in miss for miss in incident["known_misses"])
    assert any("new PC" in noise for noise in incident["known_noise"])


def test_a_manual_action_cannot_be_approved_into_running(tmp_path, license_server):
    out, incidents = draft(ENCODED, tmp_path)
    assert incidents[0]["action"]["status"] == "manual step for a person"
    result = approve(out, incidents[0]["id"], license_server)
    assert result.returncode == 1 and "step for a person" in result.stderr


def test_approval_disables_the_key_on_the_real_server(tmp_path, license_server):
    assert activate(license_server, "FQ-DEMO-0002", "machine-1")["activated"]
    out, incidents = draft(SHARING, tmp_path)
    # Point the draft at the real key's hash, as a real run's alert would.
    document = json.loads(out.read_text(encoding="utf-8"))
    log_line = json.loads((tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()[0])
    document["incidents"][0]["action"]["target_value"] = log_line["license_key_hash"]
    out.write_text(json.dumps(document), encoding="utf-8")

    result = approve(out, incidents[0]["id"], license_server)
    assert result.returncode == 0, result.stderr
    assert activate(license_server, "FQ-DEMO-0002", "machine-1")["reason"] == "disabled"
    assert activate(license_server, "FQ-DEMO-0001", "machine-9")["activated"]  # Other keys still work.
    approved = json.loads(out.read_text(encoding="utf-8"))["incidents"][0]
    assert approved["approval"]["approver"] == "Pranav" and approved["action"]["status"] == "done"
    assert approve(out, incidents[0]["id"], license_server).returncode == 1  # It can't be approved twice.


def test_the_server_refuses_a_wrong_admin_token(tmp_path, license_server):
    out, incidents = draft(SHARING, tmp_path)
    result = approve(out, incidents[0]["id"], license_server, token="wrong")
    assert result.returncode == 2 and "401" in result.stderr


def test_the_admin_endpoint_does_not_exist_without_a_token(tmp_path):
    server = subprocess.Popen([sys.executable, str(REPO_ROOT / "game/license_server.py"), "--log", str(tmp_path / "log.jsonl")],
                              stdout=subprocess.PIPE, text=True, env={k: v for k, v in os.environ.items() if k != "LICENSE_ADMIN_TOKEN"})
    try:
        url = server.stdout.readline().strip()
        request = urllib.request.Request(f"{url}/admin/disable", data=b'{"license_key_hash": "x"}', method="POST",
                                         headers={"Authorization": "Bearer "})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=10)
        assert error.value.code == 404
    finally:
        server.terminate()
        server.wait(timeout=10)
