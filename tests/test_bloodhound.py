from tests.helpers import EngagementCase

NORTH = "bloodhound/north_20260904205950_bloodhound.zip"
EAST = "bloodhound/east_20260904210044_bloodhound.zip"


class BloodHound(EngagementCase):
    """Counts on the BloodHound fixtures for the types Trove keeps."""

    def _counts(self):
        out = {}
        for rec in self.all():
            out[rec["type"]] = out.get(rec["type"], 0) + 1
        return out

    def test_the_fixture_collection_gives_accounts_groups_memberships_and_a_stated_password(self):
        self.import_fixture(EAST)
        self.import_fixture(NORTH)
        self.assertEqual(self._counts(), {"principal": 35, "group": 103, "credential": 1, "relationship": 71,
                                             "finding": 7})
        self.assertTrue(all(r["kind"] == "member_of" for r in self.all("relationship")))
        [stated] = self.all("credential")
        self.assertEqual((stated["principal"], stated["realm"]), ("samwell.tarly", "NORTH.LAB.LOCAL"))
        self.assertIn(stated["secret"], stated["prov"]["secret"]["quote"])
        self.assertEqual(stated["state"], "found")
        self.assert_citations_hold()

    def test_each_collection_on_its_own(self):
        self.import_fixture(NORTH)
        self.assertEqual(self._counts(), {"principal": 19, "group": 47, "credential": 1, "relationship": 34,
                                             "finding": 4})

    def test_enabled_accounts_open_to_a_roast_are_findings(self):
        self.import_fixture(NORTH)
        self.assertEqual(sorted(f["title"] for f in self.all("finding")),
                         ["AS-REP roastable: NORTH.LAB.LOCAL\\brandon.stark",
                          "Kerberoastable: NORTH.LAB.LOCAL\\jon.snow",
                          "Kerberoastable: NORTH.LAB.LOCAL\\sansa.stark",
                          "Kerberoastable: NORTH.LAB.LOCAL\\sql_svc"])
        self.assertEqual({f["prov"]["title"]["quote"] for f in self.all("finding")},
                         {'"dontreqpreauth": true', '"hasspn": true'})
        self.assert_citations_hold()

    def test_memberships_resolve_although_the_groups_file_is_read_before_the_users(self):
        reports = {r["source"].rsplit("_", 1)[-1]: r for r in self._import_all(EAST)}
        self.assertEqual(len(self.all("relationship")), 37)
        self.assertEqual(reports["groups.json"]["parser"], "bloodhound")
        self.assertEqual(reports["groups.json"]["counts"], {"group": 56, "relationship": 37})
        self.assertTrue(any("7 membership(s) name a member Trove does not hold" in n
                            for n in reports["groups.json"]["notes"]))

    def test_a_membership_cites_the_member_sid_and_the_members_key(self):
        self.import_fixture(EAST)
        principals = {p["id"]: p for p in self.all("principal")}
        edge = next(e for e in self.all("relationship") if e["src_id"] in principals)
        self.assertEqual(edge["prov"]["src_id"]["quote"], principals[edge["src_id"]]["sid"])
        self.assertEqual(edge["prov"]["kind"]["quote"], "Members")

    def test_domains_ous_gpos_and_containers_are_said_not_recorded(self):
        notes = [n for r in self._import_all(NORTH) for n in r["notes"]]
        self.assertTrue(any("domains; Trove has no record type" in n for n in notes))
        self.assertFalse(self.all("domain"))

    def _import_all(self, rel):
        from lootlib import ingest
        from tests import FIXTURES
        return ingest.import_path(self.eng, FIXTURES / rel)
