# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
import sys
from pathlib import Path

# PYTHONSAFEPATH or `python -P` drops the script's directory from sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lootlib.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
