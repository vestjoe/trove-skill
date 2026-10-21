import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "loot" / "scripts" / "loot.py"
sys.path.insert(0, str(SCRIPT.parent))

from lootlib import __version__  # noqa: E402


class TheEntryPoint(unittest.TestCase):
    def test_it_runs_from_any_directory_and_finds_its_package(self):
        with tempfile.TemporaryDirectory() as elsewhere:
            out = subprocess.run(
                [sys.executable, str(SCRIPT), "--version"],
                cwd=elsewhere, capture_output=True, text=True, check=True,
                env={**os.environ, "PYTHONSAFEPATH": "1"},
            )
        self.assertEqual(out.stdout.strip(), f"Trove {__version__}")


if __name__ == "__main__":
    unittest.main()
