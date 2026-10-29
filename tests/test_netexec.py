from lootlib import ingest
from tests.helpers import EngagementCase


class NetExec(EngagementCase):
    """Counts and values on the seven NetExec fixtures."""

    def _creds(self):
        return {c["principal"]: c for c in self.all("credential")}

    def _hosts(self):
        return {h["ip"]: h for h in self.all("host")}

    def test_a_spray_gives_its_one_confirmed_login_and_refuses_the_failures(self):
        report = self.import_fixture("netexec/nxc-spray.txt")
        self.assertEqual((report["parser"], report["counts"]), ("netexec", {"host": 2, "service": 1, "finding": 2, "credential": 1}))
        self.assertEqual(sorted(f["title"] for f in self.all("finding")),
                         ["Domain controller", "SMB null auth allowed"])
        self.assertEqual(self._hosts()["10.10.10.6"]["hostnames"], ["WINTERFELL"])
        rickon = self._creds()["rickon.stark"]
        self.assertEqual((rickon["realm"], rickon["secret"], rickon["state"]),
                         ("north.acme.local", "Winter2022", "confirmed"))
        self.assertTrue(rickon["prov"]["state"]["quote"].startswith("[+] "))
        self.assertTrue(any("2 login(s) failed" in n for n in report["notes"]))
        host = self._hosts()["10.10.10.5"]
        self.assertEqual((host["hostnames"], host["os"]),
                         (["KINGSLANDING"], "Windows 10 / Server 2019 Build 17763 x64"))
        self.assert_citations_hold()

    def test_a_guest_fallback_is_not_a_login_and_admin_access_is_kept(self):
        report = self.import_fixture("netexec/nxc-cred-check.txt")
        self.assertEqual(report["counts"], {"host": 4, "service": 1, "finding": 3, "credential": 2})
        self.assertEqual(sorted(self._hosts()), ["10.10.10.6", "10.10.10.7", "10.10.10.8", "10.10.10.9"])
        self.assertEqual(sorted(f["title"] for f in self.all("finding") if f["host_id"] == "host:10.10.10.7"),
                         ["SMB signing not required", "SMBv1 enabled"])
        refused = next(f for f in self.all("finding") if f["status"] == "failed")
        self.assertEqual((refused["host_id"], refused["status"]), ("host:10.10.10.8", "failed"))
        creds = self.all("credential")
        self.assertEqual(sorted(c["realm"] for c in creds), ["essos.local", "north.acme.local"])
        self.assertFalse([c for c in creds if c["realm"] == "essos.local" and c["principal"] == "rickon.stark"])
        self.assertTrue(any("as Guest" in n for n in report["notes"]))
        admin = self._creds()["Administrator"]
        self.assertEqual((admin["secret"], admin["admin_hosts"]), ("Passw0rd!", ["host:10.10.10.9"]))
        self.assertTrue(admin["prov"]["admin_hosts"][0]["quote"].endswith("(Pwn3d!)"))
        self.assertNotIn("access", admin["ext"])
        self.assertNotIn("admin_hosts", self._creds()["rickon.stark"])
        self.assertTrue(all("secret_hash" not in c for c in creds))

    def test_a_confirmed_login_names_every_host_it_worked_on_citing_the_login_line(self):
        self.import_fixture("netexec/nxc-cred-check.txt")
        creds = self._creds()
        self.assertEqual(creds["rickon.stark"]["hosts"], ["host:10.10.10.6", "host:10.10.10.8"])
        self.assertEqual([c["quote"].split()[0] for c in creds["rickon.stark"]["prov"]["hosts"]],
                         ["10.10.10.6", "10.10.10.8"])
        self.assertTrue(all(c["quote"].endswith("rickon.stark:Winter2022") for c in creds["rickon.stark"]["prov"]["hosts"]))
        self.assertEqual(creds["Administrator"]["hosts"], ["host:10.10.10.9"])
        self.assert_citations_hold()

    def test_hashes_behind_the_prefix_and_ldap_attributes_are_read(self):
        report = self.import_fixture("netexec/nxc-kerberoast.txt")
        self.assertEqual(report["counts"], {"host": 1, "service": 1, "credential": 3, "principal": 1, "group": 1, "relationship": 1})
        jon = self._creds()["jon.snow"]
        self.assertEqual((jon["hash_type"], jon["realm"]), ("krb5tgs", "NORTH.ACME.LOCAL"))
        self.assertEqual(jon["prov"]["secret_hash"]["quote"], jon["secret_hash"])
        self.assertEqual(list(self._hosts()), ["10.10.10.6"])
        edge = self.all("relationship")[0]
        self.assertEqual((edge["kind"], edge["prov"]["kind"]["quote"]), ("member_of", "memberOf"))
        self.assert_citations_hold()

    def test_every_protocol_banner_is_a_host_and_a_port_and_only_mssql_states_a_version(self):
        report = self.import_fixture("netexec/nxc-banners.txt")
        self.assertEqual(report["counts"], {"host": 4, "service": 4, "finding": 1})
        hosts = self._hosts()
        self.assertEqual(sorted(h["hostnames"][0] for h in hosts.values()), ["DC01", "DC02", "SQL1", "WS01"])
        self.assertEqual(hosts["10.10.10.7"]["os"], "Windows 10 / Server 2016 Build 14393")
        self.assertEqual(sorted(s["port"] for s in self.all("service")), [389, 445, 1433, 5985])
        svc = next(s for s in self.all("service") if s.get("version"))
        self.assertEqual((svc["host_id"], svc["port"], svc["version"]), ("host:10.10.10.7", 1433, "2019 RTM 15.0.2000"))

    def test_a_refused_operation_is_a_failed_finding_not_a_failed_login(self):
        report = self.import_fixture("netexec/nxc-null-session.txt")
        self.assertEqual(report["counts"], {"host": 1, "service": 1, "finding": 2})
        found = next(f for f in self.all("finding") if f["status"] == "failed")
        self.assertEqual((found["title"], found["description"], found["host_id"], found["status"]),
                         ("Error enumerating shares", "STATUS_ACCESS_DENIED", "host:10.10.10.5", "failed"))
        self.assertEqual(found["prov"]["status"]["quote"], "[-] Error enumerating shares:")
        self.assertFalse(any("login" in n.lower() for n in report["notes"]))

    def test_a_null_session_that_worked_is_a_finding_on_its_host(self):
        self.import_fixture("netexec/nxc-null-session.txt")
        null = next(f for f in self.all("finding") if f["status"] == "confirmed")
        self.assertEqual((null["title"], null["host_id"], null["prov"]["status"]["quote"]),
                         ("SMB null session accepted", "host:10.10.10.5", "[+] acme.local\\:"))
        self.assert_citations_hold()

    def test_a_login_with_an_empty_password_is_a_finding_naming_the_account_on_its_host(self):
        report = self.import_fixture("netexec/nxc-empty-password.txt")
        empty = {f["title"]: f for f in self.all("finding") if "empty password" in f["title"]}
        self.assertEqual(set(empty), {"SMB login with an empty password accepted (essos.local\\guest)",
                                      "SMB login with an empty password accepted (essos.local\\daario.naharis)"})
        guest = empty["SMB login with an empty password accepted (essos.local\\guest)"]
        self.assertEqual((guest["host_id"], guest["status"], guest["prov"]["status"]["quote"]),
                         ("host:10.10.10.11", "confirmed", "[+] essos.local\\guest:"))
        self.assertEqual(sorted(f["title"] for f in self.all("finding") if "empty password" not in f["title"]),
                         ["SMB null session accepted"])
        self.assertEqual(self.all("credential"), [])
        self.assertTrue(any("as Guest" in n and "essos.local\\nobody" in n for n in report["notes"]))
        self.assert_citations_hold()

    def test_an_empty_password_login_imported_twice_is_one_finding(self):
        self.import_fixture("netexec/nxc-empty-password.txt")
        self.import_fixture("netexec/nxc-empty-password.txt")
        self.assertEqual(len([f for f in self.all("finding") if "empty password" in f["title"]]), 2)

    def test_a_share_table_is_one_record_per_share_and_a_mangled_login_is_refused(self):
        report = self.import_fixture("netexec/nxc-shares-mangled.txt")
        self.assertEqual(report["counts"], {"host": 1, "service": 1, "finding": 1, "share": 5})
        shares = {s["name"]: s for s in self.all("share")}
        self.assertEqual(set(shares), {"ADMIN$", "all", "C$", "IPC$", "public"})
        self.assertEqual((shares["all"]["permissions"], shares["all"]["remark"]), ("READ,WRITE", "Basic RW share for all"))
        self.assertEqual((shares["C$"].get("permissions"), shares["C$"]["remark"]), (None, "Default share"))
        self.assert_citations_hold()

    def test_the_password_policy_is_one_finding_with_no_severity(self):
        report = self.import_fixture("netexec/nxc-password-policy.txt")
        self.assertEqual(report["counts"], {"host": 1, "service": 1, "credential": 1, "finding": 1})
        policy = self.all("finding")[0]
        self.assertEqual((policy["title"], policy["host_id"]), ("Password policy: NORTH", "host:10.10.10.6"))
        self.assertIn("Minimum password length: 5", policy["description"])
        self.assertIn("\n   Domain Password Complex: 0", policy["description"])
        self.assertNotIn("status", policy)
        self.assert_citations_hold()

    def test_a_character_beyond_ascii_early_in_a_line_moves_no_citation(self):
        path = self.tmp / "nxc-localised.txt"
        path.write_text(
            "SMB                      192.168.56.22   445    CASTELBLACK      [*] Windows Server 2019 Standard Évaluation "
            "17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)\n"
            "SMB                      192.168.56.22   445    CASTELBLACK      [+] north.sevenkingdoms.local\\jon.snow:"
            "Hïver2026! (Pwn3d!)\n", encoding="utf-8")
        ingest.import_path(self.eng, path, None)
        finding = next(f for f in self.all("finding") if f["title"] == "SMB signing not required")
        self.assertEqual(finding["prov"]["title"]["quote"], "(signing:False)")
        self.assertTrue(self._creds()["jon.snow"]["prov"]["admin_hosts"][0]["quote"].endswith("Hïver2026! (Pwn3d!)"))
        self.assert_citations_hold()
