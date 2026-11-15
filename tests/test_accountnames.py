import json

from lootlib import aiingest, ingest
from tests.helpers import EngagementCase

NXC = (b"SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 x64 "
       b"(name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)\n"
       b"SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\\arya.stark:Needle\n")
NOTE = b"Found arya.stark@north.sevenkingdoms.local:Needle in the share on winterfell.\n"
PAIR = "arya.stark@north.sevenkingdoms.local:Needle"


def field(value, evidence):
    return {"value": value, "evidence": evidence}


class AccountNames(EngagementCase):
    """One account written user@domain, DOMAIN\\user, or user with a realm."""

    def propose_pair(self):
        blob = ingest.import_data(self.eng, NOTE, "note.md")[0]["blob"]
        aiingest.check(self.eng, blob, json.dumps({"records": [{"type": "credential", "fields": {
            "principal": field("arya.stark@north.sevenkingdoms.local", PAIR),
            "secret": field("Needle", PAIR)}}]}))

    def test_a_proposed_user_at_domain_joins_the_netexec_login(self):
        self.propose_pair()
        ingest.import_data(self.eng, NXC, "nxc.txt")
        creds = self.all("credential")
        self.assertEqual([(c["principal"], c["realm"], c["secret"]) for c in creds],
                         [("arya.stark", "north.sevenkingdoms.local", "Needle")])
        self.assertEqual(creds[0]["state"], "confirmed")

    def test_the_realm_split_from_a_name_cites_the_name(self):
        self.propose_pair()
        cred = self.all("credential")[0]
        self.assertEqual(cred["id"], "credential:north.sevenkingdoms.local\\arya.stark+" + cred["id"][-8:])
        self.assertEqual(cred["prov"]["realm"], cred["prov"]["principal"])
        self.assertEqual(cred["prov"]["realm"]["quote"], PAIR)
        self.assert_citations_hold()

    def test_a_domain_backslash_name_in_a_user_list_splits(self):
        ingest.import_data(self.eng, b"north\\brandon.stark\n", "users.txt", tool="users")
        rec = self.all("principal")[0]
        self.assertEqual((rec["id"], rec["principal"], rec["realm"]),
                         ("principal:north\\brandon.stark", "brandon.stark", "north"))

    def test_a_name_with_an_at_but_no_dotted_domain_is_kept_whole(self):
        ingest.import_data(self.eng, b"svc@backup\n", "users.txt", tool="users")
        rec = self.all("principal")[0]
        self.assertEqual((rec["principal"], rec.get("realm")), ("svc@backup", None))
