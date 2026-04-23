from pathlib import Path

import yaml


def _load_schema_and_validator():
    """Load schema + validator from existing repo locations without hard-coding internals."""
    root = Path(__file__).resolve().parents[1]

    schema_candidates = [
        root / "shared" / "metadata" / "schema.yml",
        root / "shared" / "metadata" / "schema.yaml",
        root / "shared" / "schema" / "blueprint_metadata.schema.yml",
        root / "shared" / "schema" / "blueprint_metadata.schema.yaml",
    ]

    validator_candidates = [
        root / "shared" / "metadata" / "validate.py",
        root / "shared" / "schema" / "validate.py",
        root / "yaml.py",
    ]

    schema_path = next((p for p in schema_candidates if p.exists()), None)
    validator_path = next((p for p in validator_candidates if p.exists()), None)

    return schema_path, validator_path


def test_go_blueprint_metadata_fixture_exists_and_is_well_formed_yaml():
    fixture = Path("shared/metadata/go_blueprint.metadata.yml")
    assert fixture.exists(), "Expected Go metadata fixture to exist"

    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("stack") == "go"
    assert data.get("platform") == "github-actions"


def test_go_blueprint_metadata_is_schema_validation_ready():
    """
    Focused guardrail test: ensure Go metadata fixture has the expected shape
    used by the repository schema validator path.
    """
    fixture = Path("shared/metadata/go_blueprint.metadata.yml")
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))

    required_top_level = {
        "id",
        "name",
        "version",
        "platform",
        "stack",
        "blueprint_path",
        "controls",
        "tools",
        "triggers",
    }

    missing = required_top_level - set(data.keys())
    assert not missing, f"Missing expected metadata keys: {sorted(missing)}"

    assert isinstance(data["controls"], list) and data["controls"], "controls must be a non-empty list"
    assert isinstance(data["tools"], dict) and data["tools"], "tools must be a non-empty map"
    assert isinstance(data["triggers"], list) and data["triggers"], "triggers must be a non-empty list"

    # Keep this check lightweight but ensure this fixture tracks repository validator layout.
    schema_path, validator_path = _load_schema_and_validator()
    assert (
        schema_path is not None or validator_path is not None
    ), "Expected existing schema and/or validator location in repository"
