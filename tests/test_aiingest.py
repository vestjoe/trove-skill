import json

from lootlib import aiingest, rawstore
from lootlib.errors import LootError
from tests.helpers import EngagementCase


def field(value, evidence):
    return {"value": value, "evidence": evidence}


class Proposals(EngagementCase):
    def setUp(self):
        super().setUp()
        self.blob = self.import_fixture("freeform/engagement-note.md")["blob"]

    def propose(self, *recs):
        return aiingest.check(self.eng, self.blob, json.dumps({"records": list(recs)}))

    def test_a_quoted_value_is_stored_as_ai_and_cites_the_file(self):
        result = self.propose({"type": "host", "fields": {"ip": field("10.10.10.5", "web01 (10.10.10.5)")}})
        self.assertEqual(result["accepted"], 1)
        host = self.all("host")[0]
        self.assertEqual(host["prov"]["ip"]["origin"], "ai")
        self.assert_citations_hold()
        self.assertEqual(rawstore.entry(self.eng, self.blob)["ai"], "done")

    def test_hard_wrapped_evidence_still_matches(self):
        result = self.propose({"type": "finding", "fields": {"title": field(
            "Outdated Jetty", "outdated Jetty on dc01:8080")}})
        self.assertEqual(result["accepted"], 1)

    def test_an_invented_quote_takes_its_field_with_it(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup creds work"),
            "secret": field("Winter2024!", "password is Winter2024!")}})
        self.assertEqual(result["accepted"], 1)
        self.assertNotIn("secret", self.all("credential")[0])
        self.assertIn("not in the file", result["dropped"][0])

    def test_a_value_its_own_evidence_does_not_hold_is_dropped(self):
        result = self.propose({"type": "host", "fields": {"ip": field("10.10.10.50", "web01 (10.10.10.5)")}})
        self.assertEqual(result["accepted"], 0)
        self.assertIn("does not appear in its evidence", result["dropped"][0])

    def test_severity_is_refused_by_name(self):
        result = self.propose({"type": "finding", "fields": {
            "title": field("No lockout", "no lockout"), "severity": field("high", "no lockout")}})
        self.assertIn("severity", result["dropped"][0])
        self.assertNotIn("severity", self.all("finding")[0])

    def test_a_banner_is_refused_from_prose(self):
        result = self.propose({"type": "service", "fields": {
            "host": field("10.10.10.5", "web01 (10.10.10.5)"), "port": field(8080, "dc01:8080"),
            "banner": field("outdated Jetty", "outdated Jetty on")}})
        self.assertIn("banner", result["dropped"][0])
        self.assertNotIn("banner", self.all("service")[0])

    def test_a_credential_names_the_host_it_was_taken_from_as_a_list(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup creds work"),
            "host": field("10.10.10.5", "web01 (10.10.10.5)")}})
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(self.all("credential")[0]["host_id"], ["host:10.10.10.5"])
        self.assert_citations_hold()

    def test_a_credential_host_is_refused_from_prose(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup creds work over SMB on 10.10.10.6"),
            "hosts": field(["10.10.10.6"], "svc_backup creds work over SMB on 10.10.10.6")}})
        self.assertIn("hosts", result["dropped"][0])
        self.assertNotIn("hosts", self.all("credential")[0])

    def test_admin_access_is_refused_from_prose(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup creds work over SMB on 10.10.10.6"),
            "admin_hosts": field(["10.10.10.6"], "svc_backup creds work over SMB on 10.10.10.6")}})
        self.assertIn("admin_hosts", result["dropped"][0])
        self.assertNotIn("admin_hosts", self.all("credential")[0])

    def test_a_record_that_lost_its_key_is_not_written(self):
        result = self.propose({"type": "service", "fields": {
            "host": field("10.10.10.6", "SMB on 10.10.10.6"), "port": field(445, "SMB on 10.10.10.6")}})
        self.assertEqual((result["accepted"], self.all("service")), (0, []))

    def test_malformed_json_is_rejected_whole_with_where(self):
        with self.assertRaisesRegex(LootError, "line 1"):
            aiingest.check(self.eng, self.blob, '{"records": [')


class HostByName(EngagementCase):
    """A finding may name its host by a hostname the evidence states, when exactly one held host carries it."""

    def setUp(self):
        super().setUp()
        self.blob = self.import_fixture("freeform/engagement-note.md")["blob"]

    def propose(self, host, evidence="outdated Jetty on dc01:8080"):
        return aiingest.check(self.eng, self.blob, json.dumps({"records": [{"type": "finding", "fields": {
            "title": field("Outdated Jetty", evidence), "host": field(host, evidence)}}]}))

    def test_a_hostname_one_host_carries_links_to_it(self):
        self.import_fixture("nmap/nmap-basic.xml")
        result = self.propose("dc01")
        self.assertEqual(result["dropped"], [])
        self.assertEqual(self.all("finding")[0]["host_id"], "host:10.10.10.6")
        self.assert_citations_hold()

    def test_a_hostname_no_host_carries_drops_the_link_and_keeps_the_finding(self):
        result = self.propose("dc01")
        self.assertIn("names no host", result["dropped"][0])
        self.assertNotIn("host_id", self.all("finding")[0])

    def test_a_hostname_two_hosts_carry_drops_the_link(self):
        self.import_fixture("nmap/nmap-basic.xml")
        self.import_fixture("netexec/nxc-banners.txt")
        self.assertIn("names 2 hosts", self.propose("dc01")["dropped"][0])

    def test_a_hostname_its_evidence_does_not_state_is_dropped(self):
        self.import_fixture("nmap/nmap-basic.xml")
        result = self.propose("web01", evidence="outdated Jetty on dc01:8080")
        self.assertIn("does not appear in its evidence", result["dropped"][0])


class Chunks(EngagementCase):
    """A long file stays pending until every chunk has had a proposal; Trove hands out the next one."""

    def test_each_chunk_is_handed_out_once_and_the_file_is_done_after_the_last(self):
        from lootlib import ingest
        lines = [f"line {n}: nothing to see on 10.0.{n // 250}.{n % 250}\n" for n in range(900)]
        blob = ingest.import_data(self.eng, "".join(lines).encode(), "long-notes.txt")[0]["blob"]
        left, total = rawstore.chunks_left(self.eng, rawstore.entry(self.eng, blob))
        self.assertGreater(total, 1)
        seen = []
        for _ in range(total):
            result = aiingest.check(self.eng, blob, json.dumps({"records": []}))
            seen.append(result["chunk"])
            done = rawstore.entry(self.eng, blob)["ai"] == "done"
            self.assertEqual(done, not result["remaining"])
        self.assertEqual(seen, list(range(1, total + 1)))
