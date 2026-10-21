import os
import tempfile
import unittest
from pathlib import Path

from tests import FIXTURES  # noqa: F401  (re-exported for test modules)
from lootlib import engagement, ingest, rawstore, records


class EngagementCase(unittest.TestCase):
    """A fresh engagement in a temporary directory for every test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.eng = engagement.create("acme", self.tmp)
        self._env = os.environ.pop(engagement.ENV, None)

    def tearDown(self):
        if self._env is not None:
            os.environ[engagement.ENV] = self._env
        self._tmp.cleanup()

    def import_fixture(self, rel, tool=None):
        return ingest.import_path(self.eng, FIXTURES / rel, tool)[0]

    def all(self, type_name=None):
        recs = records.load_all(self.eng).values()
        return [r for r in recs if type_name is None or r["type"] == type_name]

    def assert_citations_hold(self):
        """Every citation's quote is exactly the bytes at its span."""
        for rec in self.all():
            for name, cite in rec["prov"].items():
                for ref in cite if isinstance(cite, list) else [cite]:
                    data = rawstore.read(self.eng, ref["blob"])
                    start, end = ref["span"]
                    self.assertEqual(data[start:end].decode(), ref["quote"], f"{rec['id']}.{name}")
