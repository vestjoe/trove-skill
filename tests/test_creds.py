from lootlib import ingest
from tests.helpers import FIXTURES, EngagementCase


class Creds(EngagementCase):
    """Counts and values on the credential fixtures."""

    def _by(self, account, hash_type=None):
        written = (lambda c: f"{c['realm']}\\{c['principal']}" if c.get("realm") else c["principal"])
        return next(c for c in self.all("credential")
                    if account in (c["principal"], written(c)) and (hash_type is None or c.get("hash_type") == hash_type))

    def test_every_dumped_account_is_a_hash_with_no_password(self):
        report = self.import_fixture("creds/secretsdump-ntlm.txt")
        self.assertEqual((report["parser"], report["counts"]), ("creds", {"credential": 4}))
        self.assertEqual({c["principal"] for c in self.all("credential")},
                         {"Administrator", "Guest", "svc_backup", "jdoe"})
        svc = self._by("svc_backup")
        self.assertEqual((svc["secret_hash"], svc["hash_type"], svc["state"], svc["ext"]["rid"]),
                         ("64f12cddaa88057e06a81b54e73b949b", "ntlm", "found", "1008"))
        self.assertNotIn("secret", svc)
        self.assertEqual(svc["prov"]["state"]["quote"], svc["secret_hash"])
        self.assertEqual(self._by("jdoe")["prov"]["hash_type"]["quote"], "nthash")
        self.assert_citations_hold()

    def test_a_crack_with_no_dump_makes_nothing_and_says_so(self):
        report = self.import_fixture("creds/hashcat-cracked.txt")
        self.assertEqual((report["parser"], report["counts"]), ("creds", {}))
        self.assertIn("match no credential", report["notes"][0])

    def test_a_crack_after_the_dump_fills_the_existing_credential(self):
        self.import_fixture("creds/secretsdump-ntlm.txt")
        dump_blob = self._by("svc_backup")["prov"]["principal"]["blob"]
        report = self.import_fixture("creds/hashcat-cracked.txt")
        self.assertEqual((report["new"], report["notes"]), (0, []))
        self.assertEqual(len(self.all("credential")), 4)
        svc, jdoe = self._by("svc_backup"), self._by("jdoe")
        self.assertEqual((svc["secret"], svc["state"], svc["hash_type"]), ("Password1", "cracked", "ntlm"))
        self.assertEqual(svc["prov"]["principal"]["blob"], dump_blob)
        self.assertNotEqual(svc["prov"]["secret"]["blob"], dump_blob)
        self.assertEqual(jdoe["secret"], "Summer2026!")
        self.assert_citations_hold()

    def test_an_ntds_dump_splits_domain_from_user_and_keeps_a_real_lm_hash(self):
        report = self.import_fixture("creds/secretsdump-ntds.txt")
        self.assertEqual(report["counts"], {"credential": 6})
        self.assertEqual({c["principal"] for c in self.all("credential")},
                         {"Administrator", "krbtgt", "jsmith", "legacy_svc", "SRV01$"})
        self.assertEqual({c["realm"] for c in self.all("credential")}, {"ACME"})
        self.assertIn("credential:acme\\jsmith-dbcbdeee", {c["id"] for c in self.all("credential")})
        lm = self._by("ACME\\legacy_svc", "lm")
        self.assertEqual((lm["secret_hash"], lm["prov"]["hash_type"]["quote"]),
                         ("e52cac67419a9a224a3b108f3fa6cb6d", "lmhash"))

    def test_a_plaintext_with_a_colon_survives_and_an_orphan_is_reported(self):
        self.import_fixture("creds/secretsdump-ntds.txt")
        self.assertEqual(self.import_fixture("creds/hashcat-ntds-cracked.txt")["notes"], [])
        self.assertEqual(self._by("ACME\\jsmith")["secret"], "Summer:2026!")
        orphan = self.import_fixture("creds/hashcat-orphan.txt")
        self.assertIn("match no credential", orphan["notes"][0])
        self.assertNotIn("Trombone7", orphan["notes"][0])
        self.assertEqual(len(self.all("credential")), 6)

    def test_kerberoast_hashes_name_their_account_and_a_crack_joins_them(self):
        report = self.import_fixture("creds/kerberoast-tgs.txt")
        sql = self._by("sqlsvc")
        self.assertEqual((sql["realm"], sql["hash_type"], sql["state"]), ("ACME.LOCAL", "krb5tgs", "found"))
        self.assertEqual((sql["prov"]["principal"]["quote"], sql["prov"]["hash_type"]["quote"]), ("sqlsvc", "$krb5tgs$"))
        self.assertEqual((sql["ext"]["etype"], sql["ext"]["spn"]), ("23", "MSSQLSvc/db01.acme.local:1433"))
        self.assertEqual(self._by("backupsvc")["ext"]["spn"], "acme.local\\backupsvc")
        self.assertEqual(self._by("hostgmsaweb.acme.local")["ext"]["spn"], "acme.local\\gmsaWeb$")
        cracked = self.import_fixture("creds/hashcat-kerberoast-cracked.txt")
        self.assertEqual(cracked["notes"], [])
        self.assertEqual(len(self.all("credential")), 5)
        sql = self._by("sqlsvc")
        self.assertEqual((sql["secret"], sql["state"]), ("Summer:2026!", "cracked"))
        self.assertEqual(sql["prov"]["principal"]["blob"], report["blob"])
        self.assert_citations_hold()

    def test_an_asrep_hash_keeps_its_colon_and_a_standalone_crack_names_its_owner(self):
        crack = self.import_fixture("creds/hashcat-asrep-standalone.txt")
        self.assertEqual(crack["notes"], [])
        solo = self._by("noprerequser")
        self.assertEqual((solo["secret"], solo["state"], solo["realm"]), ("Autumn2025!", "cracked", "ACME.LOCAL"))
        self.import_fixture("creds/asrep-roast.txt")
        self.assertEqual(len(self.all("credential")), 2)
        self.assertEqual(self._by("noprerequser")["secret"], "Autumn2025!")
        jsmith = self._by("jsmith")
        self.assertEqual((jsmith["hash_type"], jsmith["secret_hash"].count(":")), ("krb5asrep", 1))

    def test_netntlm_and_dcc2_are_typed_by_their_own_grammar(self):
        self.assertEqual(self.import_fixture("creds/responder-netntlm.txt")["counts"], {"host": 1, "credential": 3})
        self.assertEqual({c["principal"]: c["hash_type"] for c in self.all("credential")},
                         {"jsmith": "netntlmv2", "mfleet": "netntlmv2", "legacy_svc": "netntlmv1"})
        self.assertEqual({c["principal"]: c.get("host_id") for c in self.all("credential")},
                         {"jsmith": ["host:10.10.10.42"], "mfleet": None, "legacy_svc": None})
        self.assertEqual(self.import_fixture("creds/secretsdump-dcc2.txt")["counts"], {"credential": 2})
        dcc2 = self._by("jsmith", "dcc2")
        self.assertEqual((dcc2["ext"]["iterations"], dcc2["prov"]["hash_type"]["quote"]), ("10240", "$DCC2$"))
        self.assert_citations_hold()

    def test_the_whole_lsa_dump_is_read(self):
        report = self.import_fixture("creds/secretsdump-lsa-full.txt")
        self.assertEqual(report["counts"], {"credential": 12})
        self.assertEqual(len(report["notes"]), 1)
        self.assertIn("does not name (no $MACHINE.ACC section)", report["notes"][0])
        self.assertEqual({c.get("hash_type") for c in self.all("credential")},
                         {"ntlm", "plain_password_hex", "dpapi", "nlkm", None})
        sql = self._by("ACME\\sql_service")
        self.assertEqual((sql["secret"], sql["source"], sql["prov"]["source"]["quote"]),
                         ("P@ssw0rd:with:colons!", "MSSQLSERVER", "MSSQLSERVER"))
        self.assertEqual(self._by("ACME\\bkp_service")["prov"]["secret"]["quote"], "Sommerküche2024")
        self.assertNotIn("source", self._by("ACME\\svc_mssql", "ntlm"))
        svc, = [c for c in self.all("credential") if c["principal"] == "svc_mssql"]
        self.assertEqual((svc["realm"], svc["hash_type"]), ("ACME", "ntlm"))
        self.assertEqual([k.split(":")[0] for k in svc["keys"]],
                         ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des-cbc-md5"])
        self.assertEqual([c["quote"] for c in svc["prov"]["keys"]], svc["keys"])
        self.assert_citations_hold()

    def test_kerberos_keys_imported_alone_join_the_accounts_nt_hash_later(self):
        keys = "ACME\\svc_mssql:aes256-cts-hmac-sha1-96:" + "ab" * 32 + "\nACME\\svc_mssql:des-cbc-md5:0011223344556677\n"
        ingest.import_bytes(self.eng, keys.encode(), "keys.txt")
        self.assertEqual(len(self.all("credential")), 1)
        ingest.import_bytes(self.eng, b"ACME\\svc_mssql:1204:aad3b435b51404eeaad3b435b51404ee:"
                                      b"2c1b9e7d3f60a5c81b2e4d97f0384f8a:::\n", "ntds.txt")
        cred, = self.all("credential")
        self.assertEqual((cred["hash_type"], cred["keys"][1]), ("ntlm", "des-cbc-md5:0011223344556677"))

    def test_a_scheme_with_no_account_is_reported_and_never_given_one(self):
        report = self.import_fixture("creds/hashcat-mixed-potfile.txt")
        self.assertEqual(self.all("credential"), [])
        self.assertTrue(any("$2b$12$" in n for n in report["notes"]))
        self.assertFalse(any("Hunter2!" in n for n in report["notes"]))

    def test_a_crack_imported_before_its_dump_lands_when_the_dump_arrives(self):
        early = self.import_fixture("creds/hashcat-ntds-cracked.txt")
        self.assertIn("match no credential in this engagement yet", early["notes"][0])
        later = ingest.import_path(self.eng, FIXTURES / "creds/secretsdump-ntds.txt")
        self.assertEqual([r["status"] for r in later], ["parsed", "parsed again"])
        self.assertEqual((self._by("ACME\\jsmith")["secret"], self._by("ACME\\jsmith")["state"]),
                         ("Summer:2026!", "cracked"))
        self.assert_citations_hold()

    def test_a_password_seen_as_plaintext_and_as_its_nt_hash_is_one_credential(self):
        ingest.import_data(self.eng, b"[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
                                     b"lab\\alice:1104:aad3b435b51404eeaad3b435b51404ee:"
                                     b"8846f7eaee8fb117ad06bdd830b7586c:::\n", "sam.txt")
        ingest.import_data(self.eng, b"SMB   10.0.0.5   445   WS01   [+] lab\\alice:password \n", "nxc.txt")
        alice = self.all("credential")
        self.assertEqual(len(alice), 1)
        self.assertEqual((alice[0]["secret"], alice[0]["hash_type"], alice[0]["hosts"]),
                         ("password", "ntlm", ["host:10.0.0.5"]))
        self.assert_citations_hold()

    def test_a_dump_names_its_machine_and_its_local_accounts_are_tied_to_that_host(self):
        dump = (b"[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
                b"Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
                b"[*] Dumping LSA Secrets\n[*] $MACHINE.ACC \n"
                b"LAB\\WS01$:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n")
        early = ingest.import_data(self.eng, dump, "ws01-dump.txt")[0]
        self.assertIn("belong to WS01, which no host Trove holds is called", " ".join(early["notes"]))
        ingest.import_data(self.eng, b"SMB   10.0.0.7   445   WS01   [*] Windows (name:WS01) (domain:lab)\n", "nxc.txt")
        admin = self._by("WS01\\Administrator")
        self.assertEqual((admin["realm"], admin["host_id"]), ("WS01", ["host:10.0.0.7"]))
        self.assertEqual(self._by("LAB\\WS01$")["host_id"], ["host:10.0.0.7"])
        self.assert_citations_hold()

    def test_a_short_domain_name_joins_its_long_one(self):
        ingest.import_data(self.eng, b"[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
                                     b"LAB\\alice:1104:aad3b435b51404eeaad3b435b51404ee:"
                                     b"8846f7eaee8fb117ad06bdd830b7586c:::\n", "ntds.txt")
        ingest.import_data(self.eng, b"SMB   10.0.0.5   445   WS01   [+] lab.local\\alice:password \n", "nxc.txt")
        alice = self.all("credential")
        self.assertEqual([(c["id"].rsplit("-", 1)[0], c["realm"], c["hosts"]) for c in alice],
                         [("credential:lab.local\\alice", "lab.local", ["host:10.0.0.5"])])

    def test_a_getuserspns_table_names_the_group_each_account_is_in(self):
        self.import_fixture("creds/kerberoast-tgs.txt")
        edges = [(e["src_id"], e["dst_id"]) for e in self.all("relationship")]
        self.assertEqual(edges, [("principal:acme\\sqlsvc", "group:acme\\domain admins")])
        self.assertEqual(self.all("relationship")[0]["prov"]["kind"]["quote"], "MemberOf")
        self.assert_citations_hold()
