from lootlib import find, ingest, notes, records
from tests.helpers import FIXTURES, EngagementCase

RICKON = "credential:north.acme.local\\rickon.stark-b72c5ada"
SVC_BACKUP = "credential:acme\\svc_backup-0152f3fd"
ADMIN = "credential:essos.local\\administrator-e6686054"
LAB_ADMIN = "credential:lab-01.local\\administrator-faf6add1"
LAB_BACKUP = "credential:lab-01.local\\backup.ops-d2b7d52f"
JOJEN = "credential:north.sevenkingdoms.local\\jojen.reed-7d6f81c1"
GOADMIN = "credential:north.sevenkingdoms.local\\goadmin-80d3c1bb"


class OperatorQuestions(EngagementCase):
    """Each operator question in the spec, answered by record id over every fixture."""

    def setUp(self):
        super().setUp()
        ingest.import_path(self.eng, FIXTURES)
        self.note = notes.add(self.eng, b"come back to the 8080 admin panel", host="10.10.10.6", tags=["todo"])["id"]
        self.everything = records.load_all(self.eng)

    def ids(self, **kw):
        return {r["id"] for r in find.search(self.everything, limit=1000, **kw)[1]}

    def test_q1_what_do_i_have_on_a_host(self):
        self.assertEqual(self.ids(where=["host=10.10.10.6"]), {
            "host:10.10.10.6", "service:10.10.10.6-tcp-88", "service:10.10.10.6-tcp-445",
            "service:10.10.10.6-tcp-8080", "service:10.10.10.6-tcp-389", SVC_BACKUP, RICKON, "finding:password-policy-north-cdabb4b3",
            self.note})
        on_8 = self.ids(where=["host=10.10.10.8"])
        self.assertTrue({"host:10.10.10.8", "share:10.10.10.8-public", RICKON} <= on_8)

    def test_q2_which_credentials_work_where_and_as_admin(self):
        worked = {r["id"]: r for r in find.search(self.everything, types=["credential"], where=["hosts?"])[1]}
        self.assertEqual(set(worked), {SVC_BACKUP, RICKON, ADMIN, LAB_ADMIN, LAB_BACKUP, JOJEN, GOADMIN})
        self.assertEqual(worked[RICKON]["hosts"], ["host:10.10.10.6", "host:10.10.10.8"])
        self.assertEqual(self.ids(types=["credential"], where=["admin_hosts?"]), {ADMIN, LAB_ADMIN, LAB_BACKUP, JOJEN, GOADMIN})
        self.assertEqual(worked[ADMIN]["admin_hosts"], ["host:10.10.10.9"])
        self.assertIn("(Pwn3d!)", worked[ADMIN]["prov"]["admin_hosts"][0]["quote"])

    def test_q3_what_is_cracked_and_what_was_never_tried(self):
        cracked = self.ids(types=["credential"], where=["state=cracked"])
        self.assertEqual({rid.rsplit("-", 1)[0] for rid in cracked}, {
            "credential:acme.local\\noprerequser", "credential:acme.local\\sqlsvc", "credential:acme.local\\jsmith",
            "credential:acme\\legacy_svc", "credential:helpdesk", "credential:jdoe", "credential:svc_backup"})
        untried = self.ids(types=["credential"], where=["hosts!"])
        self.assertLessEqual(cracked - {SVC_BACKUP}, untried)
        self.assertEqual(untried & {SVC_BACKUP, RICKON, ADMIN}, set())

    def test_q4_who_is_in_a_group(self):
        self.assertEqual(self.ids(types=["relationship"], where=["dst_id=group:north.lab.local\\domain admins"]), {
            f"rel:principal:north.lab.local\\{who}-member_of-group:north.lab.local\\domain admins"
            for who in ("administrator", "eddard.stark", "goadmin")})

    def test_q5_what_i_noted_to_come_back_to(self):
        self.assertEqual(self.ids(types=["note"], where=["tags=todo"]), {self.note})
        self.assertEqual(self.everything[self.note]["host_id"], "host:10.10.10.6")
