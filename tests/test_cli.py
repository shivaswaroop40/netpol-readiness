"""End-to-end CLI smoke tests — every subcommand runs and exits sanely."""
import json
import os

from npready.cli import main

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
MINI = os.path.join(FIXTURES, "mini_cluster.yaml")


def test_derive_cli(capsys, tmp_path):
    out = tmp_path / "needed.json"
    rc = main(["derive", "--manifests", MINI, "--json", str(out)])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "NEEDED graph" in printed
    data = json.load(open(out))
    assert len(data["needed"]) > 5


def test_readiness_cli_audit_on_unprotected_deps(capsys):
    """the fixture's declared deps reach default-allow dsts -> AUDIT (exit 0), and the
    output must show the unprotected line and the gate."""
    rc = main(["readiness", "--manifests", MINI])
    printed = capsys.readouterr().out
    assert "unprotected (default-allow deps)" in printed
    assert "GATE" in printed
    assert rc == 0                                     # audit gate -> zero (nothing breaks yet)


def test_attacks_cli_lists_roster(capsys):
    rc = main(["attacks"])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "T1046" in printed                          # a real ATT&CK id
    assert "01-kubelet-rce" in printed


def test_score_cli(capsys, tmp_path):
    admit = tmp_path / "admit.json"
    legit = tmp_path / "L.json"
    atk = tmp_path / "A.json"
    json.dump([["api", "db", 5432]], open(admit, "w"))
    json.dump([["api", "db", 5432], ["web", "api", 8080]], open(legit, "w"))
    json.dump([["web", "db", 5432]], open(atk, "w"))
    rc = main(["score", "--admitted", str(admit), "--legit", str(legit), "--attacks", str(atk)])
    assert rc == 0
    printed = capsys.readouterr().out
    result = json.loads(printed)
    assert result["block_rate"] == 1.0                 # attack not admitted
    assert result["false_deny"] == 0.5                 # web->api denied
