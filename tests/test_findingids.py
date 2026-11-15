import json

from lootlib import aiingest, ingest, notes, records
from tests.helpers import FIXTURES, EngagementCase

NOTE = (b"Checked 192.168.56.45 by hand. SMB signing is not required there and\n"
        b"anonymous FTP is open on 21.\n"
        b"Same story on 192.168.56.46: SMB signing is not required there.\n")
REWRAPPED = b"Second look at 192.168.56.45. SMB signing is not\nrequired   there, still.\n"

PARSER_FINDINGS = {
    "bloodhound/east_20260904210044_bloodhound.zip": [
        "finding:as-rep-roastable-east.local-missandei-0fee584d",
        "finding:kerberoastable-east.local-gmsadragon-5066129c",
        "finding:kerberoastable-east.local-sql_svc-1421b501"],
    "bloodhound/north_20260904205950_bloodhound.zip": [
        "finding:as-rep-roastable-north.lab.local-brandon-b4afbae6",
        "finding:kerberoastable-north.lab.local-jon.snow-1202234a",
        "finding:kerberoastable-north.lab.local-sansa.sta-d0039874",
        "finding:kerberoastable-north.lab.local-sql_svc-f49e35d3"],
    "netexec/nxc-banners.txt": ["finding:smbv1-enabled-63cb031d"],
    "netexec/nxc-cred-check.txt": [
        "finding:smb-signing-not-required-4b7da04d", "finding:smbv1-enabled-4da82c07",
        "finding:winrm-refused-north.acme.local-rickon.st-d281fb81"],
    "netexec/nxc-empty-password.txt": [
        "finding:smb-login-with-an-empty-password-accepte-67ecb0de",
        "finding:smb-login-with-an-empty-password-accepte-95bb6aaf",
        "finding:smb-null-session-accepted-130520f3"],
    "netexec/nxc-failed-login.txt": ["finding:domain-controller-70f56dcb", "finding:smb-null-auth-allowed-49cd526b"],
    "netexec/nxc-log-riverrun.log": ["finding:smb-signing-not-required-da6ec8e8"],
    "netexec/nxc-null-session.txt": [
        "finding:error-enumerating-shares-2ba06254", "finding:smb-null-session-accepted-323dd196"],
    "netexec/nxc-password-policy.txt": ["finding:password-policy-north-cdabb4b3"],
    "netexec/nxc-pth-lmnt-refused.txt": ["finding:smb-signing-not-required-21488447", "finding:smbv1-enabled-85d2966d"],
    "netexec/nxc-pth.txt": ["finding:smb-signing-not-required-3b2d8545"],
    "netexec/nxc-sam-goad.log": ["finding:smb-signing-not-required-ae0523bf"],
    "netexec/nxc-sam.txt": ["finding:smb-signing-not-required-c76d7282"],
    "netexec/nxc-shares-mangled.txt": ["finding:smb-signing-not-required-0031d264"],
    "netexec/nxc-spray.txt": ["finding:domain-controller-e16ddb3e", "finding:smb-null-auth-allowed-50321cf8"],
    "nuclei/nuclei-highgarden-screen.log": ["finding:ftp-anonymous-login-at-192.168.56.70-21-07b04340"],
    "nuclei/nuclei-highgarden.json": [
        "finding:self-signed-ssl-at-192.168.56.70-443-86fe71f6",
        "finding:smb-default-login-at-192.168.56.70-445-70f445f2",
        "finding:tech-detect-microsoft-iis-at-https-highg-a122c1ca"],
    "nuclei/nuclei-highgarden.jsonl": [
        "finding:caa-fingerprint-at-sevenkingdoms.local-69910fc7",
        "finding:git-config-at-http-192.168.56.71-8080-.g-4b59558e",
        "finding:openssh-detect-at-2001-db8-5eed-70-22-b0058f20",
        "finding:self-signed-ssl-at-192.168.56.70-443-86fe71f6",
        "finding:smb-default-login-at-192.168.56.70-445-70f445f2",
        "finding:tech-detect-microsoft-iis-at-https-highg-a122c1ca"],
    "nuclei/nuclei-highgarden.txt": [
        "finding:openssh-detect-at-2001-db8-5eed-70-22-b0058f20",
        "finding:self-signed-ssl-at-192.168.56.70-443-86fe71f6",
        "finding:smb-default-login-at-192.168.56.70-445-70f445f2"],
}


def field(value, evidence):
    return {"value": value, "evidence": evidence}


class AIFindingIds(EngagementCase):
    """An AI finding is named by its title's quote and host, not by the title the model chose."""

    def setUp(self):
        super().setUp()
        self.blob = ingest.import_data(self.eng, NOTE, "pyke-notes.md")[0]["blob"]

    def propose(self, title, evidence="SMB signing is not required there", host="192.168.56.45",
                host_evidence="Checked 192.168.56.45 by hand", blob=None):
        return aiingest.check(self.eng, blob or self.blob, json.dumps({"records": [{"type": "finding", "fields": {
            "title": field(title, evidence), "host": field(host, host_evidence)}}]}))

    def test_two_titles_for_the_same_evidence_are_one_finding_with_the_later_title(self):
        self.propose("SMB signing is not required")
        self.propose("SMB signing not required")
        found = self.all("finding")
        self.assertEqual(len(found), 1, [f["id"] for f in found])
        self.assertEqual(found[0]["title"], "SMB signing not required")

    def test_the_same_quote_wrapped_differently_in_another_file_is_the_same_finding(self):
        other = ingest.import_data(self.eng, REWRAPPED, "pyke-again.md")[0]["blob"]
        self.propose("SMB signing is not required")
        self.propose("SMB signing off", evidence="SMB signing is not\nrequired   there",
                     host_evidence="Second look at 192.168.56.45", blob=other)
        self.assertEqual(len(self.all("finding")), 1)

    def test_the_same_quote_on_another_host_is_another_finding(self):
        self.propose("SMB signing is not required")
        self.propose("SMB signing is not required", host="192.168.56.46",
                     host_evidence="Same story on 192.168.56.46")
        self.assertEqual(len(self.all("finding")), 2)

    def test_a_stored_finding_keeps_its_id_when_you_decide_its_status(self):
        self.propose("SMB signing is not required")
        held = self.all("finding")[0]
        old = dict(held, id="finding:smb-signing-is-not-required-00000000")
        records._path(self.eng, held["id"]).rename(records._path(self.eng, old["id"]))
        records._path(self.eng, old["id"]).write_text(json.dumps(old))
        notes.set_status(self.eng, old["id"], "confirmed")
        found = self.all("finding")
        self.assertEqual([(f["id"], f["status"]) for f in found], [(old["id"], "confirmed")])


class ParserFindingIds(EngagementCase):
    """A parser's findings keep the ids they had before AI findings were keyed on evidence."""

    def test_every_parser_fixture_keeps_its_finding_ids(self):
        for rel, expected in PARSER_FINDINGS.items():
            with self.subTest(rel):
                self.setUp()
                ingest.import_path(self.eng, FIXTURES / rel)
                self.assertEqual(sorted(f["id"] for f in self.all("finding")), expected)
                self.tearDown()
