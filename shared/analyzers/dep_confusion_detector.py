"""
Dependency Confusion Attack Detector
=======================================
Analyzes package dependency manifests for indicators of dependency confusion
risk: internal/private package names published on public registries, packages
with suspicious version pinning, packages referencing internal registries,
and namespace squatting patterns.

Supports: Python (requirements.txt/pyproject.toml/setup.cfg), Node.js (package.json),
and generic package lists.

Check IDs
----------
DC-001   Package name matches internal naming convention but no scope prefix
DC-002   Package version pinned to exact internal-looking version (0.0.1/internal/dev)
DC-003   Package references internal registry URL in metadata
DC-004   Package name contains company/internal keyword patterns
DC-005   Package uses unpinned version (*, latest, ^, ~) — upgrade injection risk
DC-006   Package name is suspiciously short (1-2 chars) — likely typosquat target

Usage::

    from shared.analyzers.dep_confusion_detector import DepConfusionDetector, PackageEntry

    entries = [
        PackageEntry(name="mycompany-internal-utils", version="1.0.0", registry="pypi"),
        PackageEntry(name="@mycompany/auth", version="2.3.1", registry="npm"),
    ]
    detector = DepConfusionDetector(internal_keywords=["mycompany", "internal"])
    report = detector.analyze(entries)
    for finding in report.findings:
        print(finding.to_dict())
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity enumeration
# ---------------------------------------------------------------------------

class DCSeverity(str, Enum):
    """Risk severity levels for dependency confusion findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Check weight table
# Maps each check ID to the number of risk points it contributes when fired.
# Weights reflect how directly the indicator enables a live supply-chain attack.
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "DC-001": 40,  # Internal name exposed to public registry — highest hijack risk
    "DC-002": 30,  # Version sentinel used only internally leaks naming scheme
    "DC-003": 35,  # Explicit reference to internal registry in metadata
    "DC-004": 35,  # Hard-coded company pattern strongly suggests private package
    "DC-005": 25,  # Unpinned versions allow silent upgrade injection
    "DC-006": 20,  # Very short name is a prime typosquatting target
}

# Severity mapping per check ID
_CHECK_SEVERITY: Dict[str, DCSeverity] = {
    "DC-001": DCSeverity.CRITICAL,
    "DC-002": DCSeverity.HIGH,
    "DC-003": DCSeverity.CRITICAL,
    "DC-004": DCSeverity.HIGH,
    "DC-005": DCSeverity.MEDIUM,
    "DC-006": DCSeverity.LOW,
}

# Internal version sentinels that reveal a package is never meant for public distribution
_INTERNAL_VERSIONS = {
    "0.0.1",
    "0.0.0",
    "internal",
    "dev",
    "local",
    "private",
    "0.0.0-internal",
}

# Registry hostnames/substrings that indicate an internal artifact store
_INTERNAL_REGISTRY_PATTERNS = [
    "localhost",
    "127.0.0.1",
    "artifactory",
    "nexus",
    "jfrog",
    "internal.registry",
]

# Hardcoded company-naming substrings used by DC-004 (not customisable).
# These are more specific than the user-supplied keywords in DC-001.
_COMPANY_PATTERNS = [
    "corp-",
    "-corp",
    "company-",
    "-company",
    "-internal-",
    "secret-",
    "private-",
]

# Unpinned version sentinels / prefixes used by DC-005
_UNPINNED_EXACT = {"*", "latest", ""}
_UNPINNED_PREFIXES = ("^", "~", ">=")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PackageEntry:
    """Represents a single dependency declared in a manifest file."""

    name: str
    version: str = "*"
    registry: str = "unknown"
    # Path to the manifest where this entry was found — aids triage
    source_file: str = ""
    # Arbitrary key/value metadata (e.g. resolved URL, homepage, description)
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class DCFinding:
    """A single dependency confusion indicator raised against one package."""

    check_id: str
    severity: DCSeverity
    package_name: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, str]:
        """Serialise the finding to a plain dictionary for JSON/logging output."""
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def summary(self) -> str:
        """Return a single human-readable line summarising the finding."""
        return (
            f"[{self.severity.value}] {self.check_id} — {self.package_name}: {self.title}"
        )


@dataclass
class DCReport:
    """Aggregated output of a full dependency confusion analysis run."""

    findings: List[DCFinding] = field(default_factory=list)
    risk_score: int = 0
    packages_analyzed: int = 0
    # Unix timestamp — set automatically at instantiation
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings across all checks."""
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        """Number of CRITICAL-severity findings."""
        return sum(1 for f in self.findings if f.severity == DCSeverity.CRITICAL)

    @property
    def high_findings(self) -> int:
        """Number of HIGH-severity findings."""
        return sum(1 for f in self.findings if f.severity == DCSeverity.HIGH)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_check(self) -> Dict[str, List[DCFinding]]:
        """Group findings by check ID — useful for check-level triage."""
        result: Dict[str, List[DCFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.check_id, []).append(finding)
        return result

    def findings_for_package(self, package_name: str) -> List[DCFinding]:
        """Return all findings that reference the specified package name."""
        return [f for f in self.findings if f.package_name == package_name]

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a multi-line text summary suitable for console output."""
        lines = [
            f"Dependency Confusion Report",
            f"  Packages analysed : {self.packages_analyzed}",
            f"  Total findings    : {self.total_findings}",
            f"  Critical          : {self.critical_findings}",
            f"  High              : {self.high_findings}",
            f"  Risk score        : {self.risk_score}/100",
        ]
        if self.findings:
            lines.append("")
            lines.append("Findings:")
            for f in self.findings:
                lines.append(f"  {f.summary()}")
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """Serialise the full report to a plain dictionary."""
        return {
            "risk_score": self.risk_score,
            "packages_analyzed": self.packages_analyzed,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class DepConfusionDetector:
    """
    Evaluates a list of PackageEntry objects against the DC-001 through DC-006
    rule set and produces a DCReport containing all fired findings.

    Parameters
    ----------
    internal_keywords:
        Custom list of strings that, if found inside a package name, suggest the
        package is meant for internal use only (DC-001).  Defaults to a
        commonly-seen set of sentinel words.
    check_unpinned:
        When True (default) the DC-005 check fires on wildcard / floating
        version specifiers.  Set to False to suppress the check in environments
        that intentionally use loose pinning (e.g. development lockfile stubs).
    """

    _DEFAULT_KEYWORDS: List[str] = [
        "internal",
        "private",
        "corp",
        "local",
        "dev-only",
        "mycompany",
    ]

    def __init__(
        self,
        internal_keywords: Optional[List[str]] = None,
        check_unpinned: bool = True,
    ) -> None:
        self._keywords: List[str] = (
            internal_keywords if internal_keywords is not None else list(self._DEFAULT_KEYWORDS)
        )
        self._check_unpinned = check_unpinned

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, packages: List[PackageEntry]) -> DCReport:
        """
        Run all enabled checks against every package in the list.

        Returns a DCReport whose risk_score is the sum of weights for each
        *unique* check ID that fired across all packages, capped at 100.
        """
        all_findings: List[DCFinding] = []
        fired_check_ids: set = set()

        for pkg in packages:
            pkg_findings = self._check_package(pkg)
            all_findings.extend(pkg_findings)
            for f in pkg_findings:
                fired_check_ids.add(f.check_id)

        # Risk score: sum weights of unique fired check IDs, cap at 100
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_check_ids)
        risk_score = min(raw_score, 100)

        return DCReport(
            findings=all_findings,
            risk_score=risk_score,
            packages_analyzed=len(packages),
        )

    # ------------------------------------------------------------------
    # Internal per-package checks
    # ------------------------------------------------------------------

    def _check_package(self, pkg: PackageEntry) -> List[DCFinding]:
        """Run all individual checks for a single package and collect findings."""
        findings: List[DCFinding] = []

        findings.extend(self._dc001(pkg))
        findings.extend(self._dc002(pkg))
        findings.extend(self._dc003(pkg))
        findings.extend(self._dc004(pkg))
        if self._check_unpinned:
            findings.extend(self._dc005(pkg))
        findings.extend(self._dc006(pkg))

        return findings

    # ------------------------------------------------------------------
    # DC-001 — Internal keyword in name, no scoped namespace prefix
    # ------------------------------------------------------------------

    def _dc001(self, pkg: PackageEntry) -> List[DCFinding]:
        """
        Fire when the package name contains a user-supplied internal keyword
        AND the package does NOT use a scoped namespace (e.g. @org/package).
        Scoped names already have a measure of namespace protection on public
        registries, so unscoped internal names carry the most hijack risk.
        """
        name_lower = pkg.name.lower()
        # A scoped npm package starts with "@" — skip as it has namespace isolation
        if pkg.name.startswith("@"):
            return []

        matched = [kw for kw in self._keywords if kw.lower() in name_lower]
        if not matched:
            return []

        return [
            DCFinding(
                check_id="DC-001",
                severity=_CHECK_SEVERITY["DC-001"],
                package_name=pkg.name,
                title="Internal keyword in unscoped package name",
                detail=(
                    f"Package '{pkg.name}' contains internal keyword(s) "
                    f"{matched} but has no '@scope/' prefix. An attacker can "
                    f"register an identically-named package on a public registry "
                    f"to intercept dependency resolution."
                ),
                evidence=f"Matched keywords: {matched}",
                remediation=(
                    "Move the package to a scoped namespace (e.g. @yourorg/package-name) "
                    "or register the public name defensively and configure a private "
                    "registry to take precedence in your resolver."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # DC-002 — Version sentinel used exclusively for internal builds
    # ------------------------------------------------------------------

    def _dc002(self, pkg: PackageEntry) -> List[DCFinding]:
        """
        Fire when the declared version is a well-known internal build sentinel
        (e.g. '0.0.1', 'internal', 'dev').  These strings are never published
        to public registries by legitimate open-source maintainers, so their
        presence reveals a private package inadvertently listed in a public
        manifest.
        """
        if pkg.version.strip().lower() not in _INTERNAL_VERSIONS:
            return []

        return [
            DCFinding(
                check_id="DC-002",
                severity=_CHECK_SEVERITY["DC-002"],
                package_name=pkg.name,
                title="Internal-only version sentinel detected",
                detail=(
                    f"Package '{pkg.name}' declares version '{pkg.version}', "
                    f"which is a known internal-build sentinel.  This strongly "
                    f"suggests the package is private and has never been published "
                    f"to a public registry under this version, making it a "
                    f"confusion attack target."
                ),
                evidence=f"Version: '{pkg.version}'",
                remediation=(
                    "Use a real semantic version and publish a placeholder package "
                    "to the public registry, or configure your resolver to prefer "
                    "the private registry for this package."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # DC-003 — Internal registry URL in package metadata
    # ------------------------------------------------------------------

    def _dc003(self, pkg: PackageEntry) -> List[DCFinding]:
        """
        Fire when any metadata value contains a hostname or substring that
        identifies an internal artifact store (Artifactory, Nexus, jFrog,
        localhost, etc.).  This leaks the existence of a private mirror and
        confirms the package is not meant for public consumption.
        """
        matched_values: List[str] = []
        for meta_value in pkg.metadata.values():
            val_lower = meta_value.lower()
            for pattern in _INTERNAL_REGISTRY_PATTERNS:
                if pattern in val_lower:
                    matched_values.append(meta_value)
                    break  # One match per metadata field is sufficient

        if not matched_values:
            return []

        return [
            DCFinding(
                check_id="DC-003",
                severity=_CHECK_SEVERITY["DC-003"],
                package_name=pkg.name,
                title="Internal registry URL found in package metadata",
                detail=(
                    f"Package '{pkg.name}' metadata references an internal artifact "
                    f"registry (e.g. Artifactory/Nexus/jFrog/localhost).  Exposure "
                    f"of internal registry URLs in public manifests can assist "
                    f"attackers in targeting your supply chain."
                ),
                evidence=f"Metadata values: {matched_values}",
                remediation=(
                    "Remove internal registry references from published manifests. "
                    "Use private registry scoping or .npmrc/.pip.conf overrides "
                    "that are never committed to public repositories."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # DC-004 — Hardcoded company-naming substring pattern
    # ------------------------------------------------------------------

    def _dc004(self, pkg: PackageEntry) -> List[DCFinding]:
        """
        Fire when the package name contains a hardcoded company-naming substring
        (e.g. 'corp-', '-internal-', 'secret-').  Unlike DC-001 these patterns
        are fixed (not user-configurable) and represent strongly opinionated
        company naming conventions that virtually never appear in legitimate
        open-source packages.
        """
        name_lower = pkg.name.lower()
        matched = [p for p in _COMPANY_PATTERNS if p in name_lower]
        if not matched:
            return []

        return [
            DCFinding(
                check_id="DC-004",
                severity=_CHECK_SEVERITY["DC-004"],
                package_name=pkg.name,
                title="Company-specific naming pattern in package name",
                detail=(
                    f"Package '{pkg.name}' contains hardcoded company-naming "
                    f"pattern(s) {matched}.  Packages following these conventions "
                    f"are typically private and are prime candidates for "
                    f"dependency confusion attacks if listed in public manifests."
                ),
                evidence=f"Matched patterns: {matched}",
                remediation=(
                    "Rename the package to a public-friendly name and publish a "
                    "benign placeholder to the public registry, or enforce "
                    "private-registry-first resolution in your build tooling."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # DC-005 — Unpinned / floating version specifier
    # ------------------------------------------------------------------

    def _dc005(self, pkg: PackageEntry) -> List[DCFinding]:
        """
        Fire when the version is unpinned (wildcard, 'latest', or a range
        operator such as '^', '~', '>=').  Unpinned versions allow an attacker
        who registers a higher version on a public registry to silently inject
        malicious code the next time the dependency is resolved.
        """
        version_stripped = pkg.version.strip()

        is_unpinned = (
            version_stripped.lower() in _UNPINNED_EXACT
            or version_stripped.startswith(_UNPINNED_PREFIXES)
        )
        if not is_unpinned:
            return []

        return [
            DCFinding(
                check_id="DC-005",
                severity=_CHECK_SEVERITY["DC-005"],
                package_name=pkg.name,
                title="Unpinned version — upgrade injection risk",
                detail=(
                    f"Package '{pkg.name}' uses an unpinned version specifier "
                    f"'{pkg.version}'.  This allows a public registry to serve a "
                    f"higher malicious version on the next install without any "
                    f"change to the manifest."
                ),
                evidence=f"Version specifier: '{pkg.version}'",
                remediation=(
                    "Pin to an exact version (e.g. '==1.2.3' for pip, '1.2.3' for npm) "
                    "and use a lock file.  Validate digests / SBOMs in CI."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # DC-006 — Suspiciously short package basename
    # ------------------------------------------------------------------

    def _dc006(self, pkg: PackageEntry) -> List[DCFinding]:
        """
        Fire when the package's basename (stripping any '@scope/' prefix) is
        1 or 2 characters long.  Extremely short names are attractive typosquat
        targets because many real packages have names that differ by only one
        character, and attackers register the short variants to catch
        mis-typed imports.
        """
        # Strip leading "@" and take only the final path segment
        basename = pkg.name.lstrip("@").split("/")[-1]
        if len(basename) > 2:
            return []

        return [
            DCFinding(
                check_id="DC-006",
                severity=_CHECK_SEVERITY["DC-006"],
                package_name=pkg.name,
                title="Suspiciously short package name — typosquat target",
                detail=(
                    f"Package '{pkg.name}' has a very short basename ('{basename}', "
                    f"{len(basename)} char(s)).  Short names are prime typosquatting "
                    f"targets: an attacker registers a slightly different name to "
                    f"catch misspelled import statements."
                ),
                evidence=f"Basename '{basename}' has {len(basename)} character(s)",
                remediation=(
                    "Verify this dependency is intentional and consider whether a "
                    "longer, unambiguous package name is available.  Monitor the "
                    "public registry for lookalike names."
                ),
            )
        ]


# ---------------------------------------------------------------------------
# Parser utilities
# ---------------------------------------------------------------------------

def parse_requirements_txt(content: str) -> List[PackageEntry]:
    """
    Parse the text content of a pip requirements.txt file into PackageEntry objects.

    Handles the following line formats::

        # comment line                 -> skipped
        (blank line)                   -> skipped
        -r other-requirements.txt      -> skipped (recursive include directive)
        package==1.0.0                 -> name="package", version="1.0.0"
        package>=1.0.0                 -> name="package", version=">=1.0.0"
        package[extra]==1.0.0          -> name="package" (extras stripped), version="1.0.0"
        package                        -> name="package", version="*"

    Parameters
    ----------
    content:
        Raw string content of a requirements.txt file.

    Returns
    -------
    List[PackageEntry]
        One entry per non-skipped line, with ``source_file`` left empty and
        ``registry`` defaulting to ``"pypi"``.
    """
    entries: List[PackageEntry] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()

        # Skip blank lines and comment lines
        if not line or line.startswith("#"):
            continue

        # Skip recursive include directives (-r / --requirement)
        if line.startswith("-"):
            continue

        # Strip inline comments (e.g. "package==1.0.0  # some note")
        line = line.split("#")[0].strip()
        if not line:
            continue

        # Use a regex to split package name (with optional extras) from version spec.
        # Supported operators: ==, >=, <=, !=, ~=, >
        # The extras group captures "[extra,list]" and is discarded.
        match = re.match(
            r"^([A-Za-z0-9_\-\.]+)(\[[^\]]*\])?\s*([><=!~][^;#\s]*)?",
            line,
        )
        if not match:
            # Unrecognised line format — skip rather than fail
            continue

        pkg_name = match.group(1)
        version_spec = match.group(3)  # None when no version is specified

        if version_spec:
            # Normalise "==1.0.0" to "1.0.0" (exact pin, most common case)
            if version_spec.startswith("=="):
                version = version_spec[2:]
            else:
                # Keep the operator for non-exact specifiers (>=, ~=, etc.)
                version = version_spec
        else:
            # No version constraint — treat as fully unpinned
            version = "*"

        entries.append(
            PackageEntry(
                name=pkg_name,
                version=version,
                registry="pypi",
                source_file="requirements.txt",
            )
        )

    return entries
