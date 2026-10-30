import codecs
import json

from lootlib import ingest, rawstore, records
from lootlib.prov import AI, TOOL
from tests.helpers import EngagementCase


def _ref(origin, quote="x"):
    return {"blob": "sha256:00", "span": [0, 1], "quote": quote, "origin": origin}


class RawStore(EngagementCase):
    def test_the_same_bytes_twice_are_stored_once(self):
        first = self.import_fixture("nmap/nmap-basic.xml")
        second = self.import_fixture("nmap/nmap-basic.xml")
        self.assertEqual(second["status"], "already imported")
        self.assertEqual(len(rawstore.manifest(self.eng)), 1)
        self.assertEqual(first["blob"], second["blob"])

    def test_utf16_is_converted_and_the_original_kept(self):
        text = "Day 1\nweb01 is 10.10.10.5\n"
        report = ingest.import_bytes(self.eng, codecs.BOM_UTF16_LE + text.encode("utf-16-le"), "ps.txt")[0]
        lines = {m["blob"]: m for m in rawstore.manifest(self.eng)}
        self.assertEqual(len(lines), 2)
        self.assertEqual(rawstore.read(self.eng, report["blob"]).decode(), text)
        self.assertEqual(lines[report["blob"]]["encoding"], "utf-16-le")
        self.assertEqual(lines[report["blob"]]["ai"], "pending")

    def test_bytes_that_are_not_text_are_stored_and_never_queued(self):
        report = ingest.import_bytes(self.eng, b"\x89PNG\r\n\x1a\n\xff\xfe\x00", "shot.png")[0]
        self.assertIn("not text", report["status"])
        self.assertEqual(rawstore.manifest(self.eng)[0]["ai"], "binary")

    def test_chunks_cover_the_data_and_cut_at_newlines(self):
        data = b"".join(b"line %d\n" % i for i in range(5000))
        spans = rawstore.chunks(data, 1000)
        self.assertEqual(spans[0][0], 0)
        self.assertEqual(spans[-1][1], len(data))
        self.assertTrue(all(data[e - 1:e] == b"\n" for _, e in spans))


class Merge(EngagementCase):
    def _host(self, origin, os_name, hostnames=()):
        rec = records.new("host")
        records.set_field(rec, "ip", "10.0.0.1", _ref(origin, "10.0.0.1"))
        records.set_field(rec, "os", os_name, _ref(origin, os_name))
        if hostnames:
            records.set_field(rec, "hostnames", list(hostnames), [_ref(origin, h) for h in hostnames])
        return rec

    def test_a_tool_value_replaces_a_guess_and_a_guess_never_replaces_a_tool_value(self):
        records.put_all(self.eng, [self._host(AI, "Linux?")])
        records.put_all(self.eng, [self._host(TOOL, "Linux 5.15")])
        records.put_all(self.eng, [self._host(AI, "Windows")])
        self.assertEqual(self.all("host")[0]["os"], "Linux 5.15")

    def test_at_equal_authority_the_later_value_wins(self):
        records.put_all(self.eng, [self._host(TOOL, "Linux")])
        records.put_all(self.eng, [self._host(TOOL, "Linux 5.15")])
        self.assertEqual(self.all("host")[0]["os"], "Linux 5.15")

    def test_list_fields_union_and_keep_a_citation_per_element(self):
        records.put_all(self.eng, [self._host(TOOL, "Linux", ["a.lab"])])
        records.put_all(self.eng, [self._host(AI, "Linux", ["a.lab", "b.lab"])])
        host = self.all("host")[0]
        self.assertEqual(host["hostnames"], ["a.lab", "b.lab"])
        self.assertEqual([r["origin"] for r in host["prov"]["hostnames"]], [TOOL, AI])

    def test_a_field_without_a_citation_is_refused(self):
        from lootlib.errors import LootError
        with self.assertRaises(LootError):
            records.set_field(records.new("host"), "ip", "10.0.0.1", None)

    def test_ids_come_from_key_fields(self):
        cred = records.new("credential", principal="Admin", realm="LAB", secret="x")
        self.assertTrue(records.make_id(cred).startswith("credential:lab\\admin+"))
        self.assertEqual(records.make_id(records.new("principal", principal="svc")), "principal:svc")
        svc = records.new("service", host_id="host:10.0.0.1", port=53)
        self.assertEqual(records.make_id(svc), "service:10.0.0.1-tcp-53")

    def _cred(self, ticket, secret=None, taken_from=None):
        rec = records.new("credential")
        if taken_from:
            records.set_field(rec, "host_id", [taken_from], [_ref(TOOL, taken_from)])
        records.set_field(rec, "principal", "svc", _ref(TOOL, "svc"))
        records.set_field(rec, "realm", "LAB.LOCAL", _ref(TOOL, "LAB.LOCAL"))
        records.set_field(rec, "secret_hash", ticket, _ref(TOOL, ticket))
        records.set_field(rec, "hash_type", "krb5tgs", _ref(TOOL, "$krb5tgs$"))
        if secret:
            records.set_field(rec, "secret", secret, _ref(TOOL, secret))
        records.set_field(rec, "state", "cracked" if secret else "found", _ref(TOOL, secret or ticket))
        return rec

    def test_a_crack_of_another_roast_marks_the_accounts_ticket_cracked(self):
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$aaaa")])
        counts = records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$bbbb", "Winter1")])
        self.assertEqual(counts, (0, 1))
        creds = self.all("credential")
        self.assertEqual([(c["secret"], c["state"]) for c in creds], [("Winter1", "cracked")])

    def test_merged_captures_keep_every_host_they_were_taken_from(self):
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$aaaa", taken_from="host:10.0.0.11")])
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$bbbb", taken_from="host:10.0.0.22")])
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$cccc", "Winter1")])
        cred, = self.all("credential")
        self.assertEqual((cred["state"], sorted(cred["host_id"])), ("cracked", ["host:10.0.0.11", "host:10.0.0.22"]))
        self.assertEqual(len(cred["prov"]["host_id"]), 2)

    def test_a_single_host_written_by_an_older_loot_reads_as_a_list(self):
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$aaaa")])
        path, = self.eng.records.glob("credential/*.json")
        old = json.loads(path.read_text())
        old["host_id"], old["prov"]["host_id"] = "host:10.0.0.11", _ref(TOOL, "10.0.0.11")
        path.write_text(json.dumps(old))
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$bbbb", "Winter1", taken_from="host:10.0.0.22")])
        cred, = self.all("credential")
        self.assertEqual(sorted(cred["host_id"]), ["host:10.0.0.11", "host:10.0.0.22"])

    def test_a_ticket_stays_apart_when_the_account_has_two_passwords(self):
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$bbbb", "Winter1"),
                                   self._cred("$krb5tgs$23$*svc*$cccc", "Spring2")])
        records.put_all(self.eng, [self._cred("$krb5tgs$23$*svc*$aaaa")])
        states = sorted(c["state"] for c in self.all("credential"))
        self.assertEqual(states, ["cracked", "cracked", "found"])
