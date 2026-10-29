import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SAMPLES = ROOT / "tests" / "samples"
CORPUS = ROOT / "tests" / "corpus" / "goad"
sys.path.insert(0, str(ROOT / "loot" / "scripts"))
