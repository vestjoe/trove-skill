import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def load_make():
    spec = importlib.util.spec_from_file_location("make_diagrams", ROOT / "diagrams/make.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Diagrams(unittest.TestCase):
    def test_every_image_a_page_shows_exists(self):
        for page in DOCS.glob("*.md"):
            for target in re.findall(r"!\[[^\]]*\]\(([^)#\s]+)", page.read_text()):
                with self.subTest(page=page.name, image=target):
                    self.assertTrue((DOCS / target).is_file())

    def test_diagrams_match_what_the_runs_print_now(self):
        files = load_make().build()
        stale = [p.name for p, text in files.items() if not p.is_file() or p.read_text() != text]
        self.assertEqual(stale, [], "run diagrams/make.py and commit the result")

    def test_each_diagram_is_shown_in_both_themes(self):
        shown = "".join(p.read_text() for p in DOCS.glob("*.md"))
        for svg in (DOCS / "assets/diagrams").glob("*.svg"):
            scheme = "light" if svg.stem.endswith("-light") else "dark"
            with self.subTest(svg=svg.name):
                self.assertIn(f"assets/diagrams/{svg.name}#only-{scheme})", shown)


if __name__ == "__main__":
    unittest.main()
