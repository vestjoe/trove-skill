import subprocess
import sys

from lootlib import engagement
from tests.helpers import EngagementCase
from tests.test_smoke import SCRIPT


class Lock(EngagementCase):
    def _note(self):
        return subprocess.Popen([sys.executable, str(SCRIPT), "note", "waited", "-e", str(self.eng.root)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_a_writer_waits_for_the_one_holding_the_engagement(self):
        with engagement.locked(self.eng, write=True):
            second = self._note()
            with self.assertRaises(subprocess.TimeoutExpired):
                second.wait(timeout=2)
        out, err = second.communicate(timeout=30)
        self.assertEqual((second.returncode, err), (0, ""))
        self.assertEqual([r["text"] for r in self.all("note")], ["waited"])

    def test_readers_share_the_lock(self):
        with engagement.locked(self.eng, write=False):
            status = subprocess.run([sys.executable, str(SCRIPT), "status", "-e", str(self.eng.root)],
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(status.returncode, 0)

    def test_an_engagement_holding_a_symbolic_link_is_not_opened(self):
        target = self.tmp / "outside.txt"
        target.write_text("untouched\n")
        (self.eng.root / "raw" / "planted.tmp").symlink_to(target)
        out = subprocess.run([sys.executable, str(SCRIPT), "note", "x", "-e", str(self.eng.root)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 1)
        self.assertIn("is a symbolic link", out.stderr)
        self.assertEqual(target.read_text(), "untouched\n")
