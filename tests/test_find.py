from lootlib import find, records
from lootlib.errors import LootError
from tests.helpers import EngagementCase


class Find(EngagementCase):
    def setUp(self):
        super().setUp()
        self.import_fixture("nmap/nmap-basic.xml")
        self.everything = records.load_all(self.eng)

    def ids(self, **kw):
        return {r["id"] for r in find.search(self.everything, **kw)[1]}

    def test_conditions_by_type_and_value(self):
        self.assertEqual(self.ids(types=["service"], where=["port=445"]), {"service:10.10.10.6-tcp-445"})
        self.assertEqual(len(self.ids(types=["service"], where=["port=22,445"])), 2)
        self.assertEqual(len(self.ids(types=["service"], where=["port>1000"])), len(
            [r for r in self.everything.values() if r["type"] == "service" and r["port"] > 1000]))

    def test_contains_exists_and_aliases(self):
        self.assertTrue(self.ids(types=["service"], where=["product~openssh"]))
        self.assertEqual(self.ids(types=["host"], where=["os?"]), {"host:10.10.10.5"})
        self.assertEqual(self.ids(types=["host"], where=["os!"]), {"host:10.10.10.6"})
        self.assertTrue(self.ids(where=["host=host:10.10.10.5"]))

    def test_a_bare_ip_matches_a_host_link_and_nothing_else(self):
        linked = self.ids(where=["host=host:10.10.10.5"])
        self.assertEqual(self.ids(where=["host=10.10.10.5"]), linked)
        self.assertEqual(self.ids(where=["host!=10.10.10.5"]) & linked, set())
        self.assertEqual(self.ids(types=["host"], where=["hostnames=10.10.10.5"]), set())

    def test_a_credential_is_found_by_a_host_it_worked_on(self):
        self.import_fixture("netexec/nxc-cred-check.txt")
        everything = records.load_all(self.eng)
        hits = find.search(everything, types=["credential"], where=["hosts=10.10.10.8"])[1]
        self.assertEqual([r["principal"] for r in hits], ["rickon.stark"])
        self.assertEqual(find.search(everything, types=["credential"], where=["host=10.10.10.8"])[1], hits)
        self.assertIn("credential:north.acme.local\\rickon.stark+b72c5ada",
                      {r["id"] for r in find.search(everything, where=["host=10.10.10.8"])[1]})

    def test_a_host_query_returns_the_host_itself_with_its_links(self):
        self.assertEqual(self.ids(where=["host=10.10.10.6"]),
                         {"host:10.10.10.6"} | self.ids(types=["service"], where=["host=10.10.10.6"]))
        self.assertEqual(self.ids(types=["host"], where=["host=10.10.10.6"]), {"host:10.10.10.6"})

    def test_admin_hosts_take_a_bare_ip(self):
        self.import_fixture("netexec/nxc-cred-check.txt")
        everything = records.load_all(self.eng)
        hits = find.search(everything, types=["credential"], where=["admin_hosts=10.10.10.9"])[1]
        self.assertEqual([r["principal"] for r in hits], ["Administrator"])

    def test_free_text_needs_every_word(self):
        self.assertEqual(self.ids(text="ssh openssh"), {"service:10.10.10.5-tcp-22"})
        self.assertEqual(self.ids(text="ssh windows"), set())

    def test_an_unknown_field_is_an_error_that_lists_the_valid_ones(self):
        with self.assertRaisesRegex(LootError, "valid: .*port"):
            find.search(self.everything, types=["service"], where=["ports=445"])

    def test_origin_filters_by_who_said_it(self):
        self.assertEqual(len(self.ids(origin="tool")), len(self.everything))
        self.assertEqual(self.ids(origin="ai"), set())
