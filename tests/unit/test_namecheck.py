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

    def test_a_registered_term_is_caught(self, tmp_path):
        """Uses a harmless canary rather than a real term.

        The genuine terms are held as digests precisely so they do not appear in
        plaintext in a public repository, and this file is public. Planting a
        real one here would put back exactly what the digests remove.
        """
        result = self._plant(tmp_path, "a line containing namecheckcanary\n")
        assert result.returncode == 1
        assert result.returncode == 1

    def test_case_insensitive(self, tmp_path):
        result = self._plant(tmp_path, "See NameCheckCanary.\n")
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


def _plant_repo(root, *messages):
    """A throwaway git repository with the given commit messages.

    The commit tests plant their own history rather than reading this
    repository's. Depending on the ambient repo made the suite environment
    coupled: actions/checkout clones with depth 1, so HEAD~1 does not resolve in
    CI and a test that passed locally failed on every Python version.
    """
    root.mkdir(parents=True, exist_ok=True)
    for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@t"],
                ["git", "config", "user.name", "t"]):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)
    for i, message in enumerate(messages):
        (root / f"f{i}.txt").write_text(f"content {i}\n")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-q", "-m", message],
                       cwd=root, check=True, capture_output=True)
    return root


class TestCommitMessages:
    def test_a_clean_range_of_more_than_one_commit_passes(self, tmp_path):
        """The range must contain commits for the result to mean anything.

        The first version used HEAD~0..HEAD, the empty range, so it scanned zero
        messages and would have passed against a scanner that read none.
        """
        repo = _plant_repo(tmp_path / "clean", "first commit", "second commit")
        result = run_namecheck("--repo", str(repo), "--commits", "HEAD~1..HEAD")
        assert result.returncode == 0, result.stderr
        assert "commit messages in HEAD~1..HEAD clean" in result.stdout

    def test_a_banned_term_in_a_commit_message_is_caught(self, tmp_path):
        """The commit scan must be able to fail, not merely to run."""
        repo = _plant_repo(tmp_path / "dirty", "a commit mentioning namecheckcanary")
        # --repo points the commit scan at the planted history. Without it the
        # scanner reads THIS repository's log whatever cwd is set to, and the
        # test would pass while scanning the wrong commits.
        out = run_namecheck("--repo", str(repo), "--commits", "HEAD")
        assert out.returncode == 1, out.stdout
        assert "forbidden term" in out.stderr
