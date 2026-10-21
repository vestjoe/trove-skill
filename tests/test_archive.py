from lootlib import rawstore
from tests.helpers import EngagementCase


class Archive(EngagementCase):
    """Behaviour on the archive fixtures."""

    def _import(self, rel):
        from lootlib import ingest
        from tests import FIXTURES
        return ingest.import_path(self.eng, FIXTURES / rel)

    def _derived(self):
        return [m for m in rawstore.manifest(self.eng) if m["derived_from"]]

    def test_a_zip_of_a_scan_parses_as_the_scan_and_cites_the_member(self):
        reports = self._import("archive/scans.zip")
        self.assertEqual([(r["source"], r.get("parser")) for r in reports[1:]], [("scans.zip/nmap-basic.xml", "nmap")])
        self.assertEqual(reports[1]["counts"], {"host": 2, "service": 6})
        [member] = self._derived()
        self.assertEqual(member["derived_from"], reports[0]["blob"])
        self.assertTrue(all(h["prov"]["ip"]["blob"] == member["blob"] for h in self.all("host")))
        self.assert_citations_hold()

    def test_an_encrypted_member_is_refused_by_name_and_its_neighbour_imported(self):
        reports = {r["source"]: r for r in self._import("archive/mixed.zip")}
        self.assertIn("encrypted", reports["mixed.zip/locked.txt"]["status"])
        self.assertEqual(reports["mixed.zip/notes.txt"]["status"], "pending AI extraction")
        self.assertEqual([m["source"] for m in self._derived()], ["mixed.zip/notes.txt"])

    def test_a_nested_zip_is_stored_and_not_opened(self):
        reports = self._import("archive/nested.zip")
        self.assertIn("archive inside an archive", reports[1]["status"])
        self.assertEqual([(m["source"], m["ai"]) for m in self._derived()], [("nested.zip/scans.zip", "refused")])
        self.assertEqual(self.all(), [])

    def test_os_metadata_inside_a_zip_is_not_kept(self):
        self._import("archive/finder.zip")
        self.assertEqual([m["source"] for m in self._derived()], ["finder.zip/nmap-basic.xml"])

    def test_importing_the_same_zip_twice_adds_nothing(self):
        self._import("archive/scans.zip")
        before = (len(rawstore.manifest(self.eng)), len(self.all()))
        again = self._import("archive/scans.zip")
        self.assertEqual([r["status"] for r in again], ["already imported"])
        self.assertEqual((len(rawstore.manifest(self.eng)), len(self.all())), before)

    def test_a_bloodhound_zip_routes_each_collector_file_to_bloodhound(self):
        reports = self._import("bloodhound/north_20260904205950_bloodhound.zip")
        self.assertEqual({r.get("parser") for r in reports[1:]}, {"bloodhound"})
        self.assertEqual(len(reports), 8)

    def test_a_corrupt_member_is_refused_not_a_crash(self):
        import io
        import zipfile
        from lootlib.parsers import archive
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", "hello world " * 200)
        data = bytearray(buf.getvalue())
        data[35] ^= 0xFF
        [member] = archive.members(bytes(data))
        self.assertIn("could not be read out of the archive", member.refused)
