"""Adapter for pq-code-package/mlkem-native and mldsa-native.

Both ship an ACVP harness that downloads NIST vectors at a version they pin
themselves. That is convenient for them and wrong for us: substrate and corpus
are orthogonal axes, and letting each substrate choose its own corpus is how a
property of stale bundled data gets reported as a coverage finding.

So the corpus is exported from cupel's pinned, hash-verified cache into the
layout the harness expects. Its client only fetches when a file is absent, so a
pre-populated cache directory is used as-is and no network call happens. The
release id doubles as the version directory name, which keeps the provenance of
a run visible in its own path.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..vectors import lock as lockmod
from ..vectors import pins as pinsmod

# What each harness's client expects to find. Read from their acvp_client.py:
# only prompt.json and expectedResults.json are consumed, never
# internalProjection.json, so the reason labels are invisible to the harness.
HARNESS_FILES = ("prompt.json", "expectedResults.json")

TARGETS = {
    "mlkem-native": {
        "repo": "pq-code-package/mlkem-native",
        "algorithm": "ML-KEM",
        "dirs": ("ML-KEM-keyGen-FIPS203", "ML-KEM-encapDecap-FIPS203",
                 "ML-KEM-encapDecap-FIPS203-tr1"),
        "make_target": "run_acvp",
    },
    "mldsa-native": {
        "repo": "pq-code-package/mldsa-native",
        "algorithm": "ML-DSA",
        "dirs": ("ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204",
                 "ML-DSA-sigGen-FIPS204-tr1", "ML-DSA-sigVer-FIPS204"),
        "make_target": "run_acvp",
    },
}


def tree(target: str) -> Path:
    return pinsmod.REPO / "vendor" / target


def export_corpus(target: str, release_id: str, entries: dict) -> tuple[Path, int]:
    """Materialise the pinned corpus where the harness will find it."""
    spec = TARGETS[target]
    dest = tree(target) / "test" / "acvp" / ".acvp-data" / release_id / "files"
    n = 0
    for vdir in spec["dirs"]:
        out = dest / vdir
        out.mkdir(parents=True, exist_ok=True)
        for name in HARNESS_FILES:
            data = lockmod.ensure(release_id, pinsmod.vector_path(vdir, name), entries)
            (out / name).write_bytes(data)
            n += 1
    return dest, n


@dataclass
class RunResult:
    target: str
    release: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        return self.returncode == 0

    def summary(self) -> str:
        tail = [ln for ln in self.stdout.splitlines() if ln.strip()][-3:]
        return " | ".join(tail) if tail else self.stderr.strip()[-200:]


def run_acvp(target: str, release_id: str, jobs: int = 16, timeout: int = 3600) -> RunResult:
    """Run the harness against the exported corpus. No network is reached."""
    spec = TARGETS[target]
    proc = subprocess.run(
        ["make", spec["make_target"], f"ACVP_VERSION={release_id}", f"-j{jobs}"],
        cwd=tree(target), capture_output=True, text=True, timeout=timeout,
    )
    return RunResult(target, release_id, proc.returncode, proc.stdout, proc.stderr)


def build(target: str, jobs: int = 16, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["make", "acvp", f"-j{jobs}"],
        cwd=tree(target), capture_output=True, text=True, timeout=timeout,
    )


def clean(target: str) -> None:
    subprocess.run(["make", "clean"], cwd=tree(target), capture_output=True, text=True)
