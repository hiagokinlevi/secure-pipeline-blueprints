import json

from shared import severity_gate


def _write_json(tmp_path, payload):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_main_branch_default_is_strict_and_fails_on_high(tmp_path):
    p = _write_json(
        tmp_path,
        {"vulnerabilities": [{"name": "pkg-a", "severity": "high"}]},
    )

    code = severity_gate.main(["--input", str(p), "--branch", "main"])
    assert code == 1


def test_feature_branch_default_is_relaxed_and_passes_high(tmp_path):
    p = _write_json(
        tmp_path,
        {"vulnerabilities": [{"name": "pkg-b", "severity": "high"}]},
    )

    code = severity_gate.main(["--input", str(p), "--branch", "feature/my-work"])
    assert code == 0


def test_explicit_threshold_overrides_branch_default(tmp_path):
    p = _write_json(
        tmp_path,
        {"vulnerabilities": [{"name": "pkg-c", "severity": "medium"}]},
    )

    code = severity_gate.main([
        "--input",
        str(p),
        "--branch",
        "feature/my-work",
        "--threshold",
        "medium",
    ])
    assert code == 1


def test_invalid_threshold_returns_config_error(tmp_path):
    p = _write_json(tmp_path, {"vulnerabilities": []})
    code = severity_gate.main(["--input", str(p), "--threshold", "urgent"])
    assert code == 2
