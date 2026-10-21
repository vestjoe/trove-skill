import contextlib
import io
import json
import os

from lootlib import aiingest, cli, notes, records
from lootlib.prov import AI, TOOL
from tests.helpers import EngagementCase

NOTE = (b"Administrator on ACME was cracked, per hashcat.\n"
        b"svc_backup:Summer2024! from the share\n"
        b"MSSQL on castelblack accepts jsmith? try xp_cmdshell later\n"
        b"dupbox\n")


def field(value, evidence):
    return {"value": value, "evidence": evidence}


class AiGuards(EngagementCase):
    """What an AI proposal may not do to a tool's facts, asked through ``find`` as the operator asks."""

    def setUp(self):
        super().setUp()
        self.import_fixture("creds/secretsdump-ntds.txt")
        self.import_fixture("netexec/nxc-cred-check.txt")
        self.blob = notes.add(self.eng, NOTE)["blob"]

    def propose(self, *recs):
        return aiingest.check(self.eng, self.blob, json.dumps({"records": list(recs)}))

    def find(self, *where):
        argv = ["find", "--type", "credential", "--limit", "1000"]
        for w in where:
            argv += ["--where", w]
        out = io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(argv), 0)
        finally:
            os.chdir(cwd)
        return out.getvalue()

    def test_h4a_q3_a_note_saying_cracked_does_not_make_a_dumped_hash_cracked(self):
        self.propose({"type": "credential", "fields": {
            "principal": field("Administrator", "Administrator on ACME was cracked"),
            "realm": field("ACME", "Administrator on ACME was cracked"),
            "state": field("cracked", "was cracked")}})
        self.assertNotIn("ACME\\Administrator", self.find("state=cracked").replace("acme\\administrator", "ACME\\Administrator"))
        self.assertIn("state       found   [tool", self.find("principal=Administrator", "realm=ACME"))

    def test_h4a_an_ai_state_never_outranks_a_tool_state_whichever_record_is_written_first(self):
        tool = self.all("credential")
        admin = next(c for c in tool if c["principal"] == "Administrator" and c.get("realm") == "ACME")
        ai_ref = dict(admin["prov"]["state"], origin=AI)
        guess = records.new("credential")
        records.set_field(guess, "principal", "Administrator", ai_ref)
        records.set_field(guess, "realm", "ACME", ai_ref)
        records.set_field(guess, "state", "cracked", ai_ref)
        records.put_all(self.eng, [guess])
        merged = next(c for c in self.all("credential") if c["principal"] == "Administrator" and c.get("realm") == "ACME")
        self.assertEqual((merged["state"], merged["prov"]["state"]["origin"]), ("found", TOOL))

    def test_h5a_q2_a_password_in_the_wrong_case_is_not_stored(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup:Summer2024!"),
            "secret": field("SUMMER2024!", "svc_backup:Summer2024!")}})
        self.assertNotIn("SUMMER2024!", self.find())
        self.assertTrue(any(".secret:" in d and "character for character" in d for d in result["dropped"]))

    def test_h5a_an_account_name_in_the_wrong_case_is_not_stored(self):
        self.propose({"type": "credential", "fields": {
            "principal": field("SVC_BACKUP", "svc_backup:Summer2024!"),
            "secret": field("Summer2024!", "svc_backup:Summer2024!")}})
        self.assertNotIn("SVC_BACKUP", self.find())

    def test_h5b_q1_a_credential_is_not_tied_to_a_host_its_evidence_never_names(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("svc_backup", "svc_backup:Summer2024!"),
            "secret": field("Summer2024!", "svc_backup:Summer2024!"),
            "host_id": field("10.10.10.8", "dupbox")}})
        self.assertNotIn("svc_backup", self.find("host=castelblack"))
        self.assertIn("Summer2024!", self.find("principal=svc_backup"))
        self.assertTrue(any("host_id" in d and "does not appear" in d for d in result["dropped"]))

    def test_h5b_a_credential_host_its_evidence_does_name_is_kept(self):
        self.propose({"type": "credential", "fields": {
            "principal": field("jsmith", "accepts jsmith?"),
            "host_id": field("castelblack", "MSSQL on castelblack")}})
        self.assertIn("credential:jsmith", self.find("host=castelblack"))

    def test_h5d_q3_an_ai_credential_state_beyond_found_is_refused(self):
        result = self.propose({"type": "credential", "fields": {
            "principal": field("jsmith", "accepts jsmith?"),
            "state": field("confirmed", "accepts")}})
        self.assertNotIn("confirmed   [ai", self.find())
        self.assertTrue(any("state" in d and "tool" in d for d in result["dropped"]))

    def test_a_capture_does_not_take_the_ntlm_label_a_hashless_proposal_left(self):
        ref = dict(self.all("credential")[0]["prov"]["principal"], origin=AI)
        first, second = records.new("credential"), records.new("credential")
        for rec in (first, second):
            records.set_field(rec, "principal", "bob", ref)
        records.set_field(first, "hash_type", "ntlm", ref)
        records.set_field(second, "secret_hash", "bob::ACME:1122334455667788:00aa:0101", ref)
        records.set_field(second, "hash_type", "netntlmv2", ref)
        records.put_all(self.eng, [first])
        records.put_all(self.eng, [second])
        bob = next(c for c in self.all("credential") if c["principal"] == "bob")
        self.assertFalse(bob.get("secret_hash") and bob.get("hash_type") == "ntlm")
