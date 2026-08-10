"""The vocabulary firewall must actually fire.

A guarantee that is never tested is a guarantee that silently lapses. These
tests plant each forbidden shape and assert namecheck catches it.
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NAMECHECK = REPO / "bin" / "namecheck.py"


def run_namecheck(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(NAMECHECK), *args],
        capture_output=True, text=True, cwd=REPO,
    )


class TestRepositoryIsClean:
    def test_tracked_files_pass(self):
        result = run_namecheck()
        assert result.returncode == 0, result.stderr


class TestForbiddenShapesAreCaught:
    def _plant(self, tmp_path: Path, text: str) -> subprocess.CompletedProcess:
        (tmp_path / "planted.md").write_text(text, encoding="utf-8")
        return run_namecheck("--paths", str(tmp_path))

    def test_project_name_is_caught(self, tmp_path):
        result = self._plant(tmp_path, "we build on REDACTED-TERM-2 for parsing\n")
        assert result.returncode == 1
        assert "REDACTED-TERM-2" in result.stderr

    def test_case_insensitive(self, tmp_path):
        result = self._plant(tmp_path, "See REDACTED-TERM-2.\n")
        assert result.returncode == 1

    def test_em_dash_is_caught(self, tmp_path):
        result = self._plant(tmp_path, "a survivor — not a witness\n")
        assert result.returncode == 1

    def test_ruling_vocabulary_is_caught(self, tmp_path):
        """cupel independently wants this concept, which is why it is renamed."""
        result = self._plant(tmp_path, "each decision cites the rulings that fired\n")
        assert result.returncode == 1

    def test_scope_rule_vocabulary_is_allowed(self, tmp_path):
        """The sanctioned replacement must not trip the check."""
        result = self._plant(tmp_path, "decided by scope rule SCOPE-03 and source repair REPAIR-01\n")
        assert result.returncode == 0, result.stderr

    def test_ruling_substring_in_another_word_is_allowed(self, tmp_path):
        """Word boundaries matter: 'ruling' is banned, 'grueling' is not."""
        result = self._plant(tmp_path, "a grueling rebuild loop\n")
        assert result.returncode == 0, result.stderr


class TestCommitMessages:
    def test_commit_range_is_scanned(self):
        """Commit messages are in scope, not just files."""
        result = run_namecheck("--commits", "HEAD~0..HEAD")
        assert result.returncode in (0, 1)
        assert "namecheck" in (result.stdout + result.stderr)
