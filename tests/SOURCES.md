# Fixture sources

The tool source each synthetic fixture under `tests/fixtures/` was built from. Kept outside `tests/fixtures/` because every file there is imported by the end-to-end tests.

## netexec

The files listed here are **synthetic-from-source**: each line is built from the
format string in the tool's published source, not captured from a run. The column
prefix copies the real NetExec files in `tests/corpus/goad/`. Hosts, names and
passwords are invented lab values.

| File | Built from |
|---|---|
| `nxc-sam.txt` | NetExec `nxc/protocols/smb.py` (main `89a698d`): `sam()` prints `display("Dumping SAM hashes")`, each impacket SAM line through `highlight()`, then `success("Added N SAM hashes to the database")`. SAM line: impacket `secretsdump.py` `"%s:%d:%s:%s:::"` |
| `nxc-ntds.txt` | NetExec `smb.py` `ntds()`: `success("Dumping the NTDS, this could take a while so go grab a redbull...")`, each secret through `highlight()` with its `(status=…)` suffix removed, then the `Dumped N NTDS hashes` and `grep -iv disabled` lines. NTDS line: impacket `"%s:%s:%s:%s:::"`; `domain\user` only when the account has a UPN (impacket master `75938fc`, `secretsdump.py:3072-3074`) |
| `nxc-pth.txt` | NetExec `smb.py:572-605` `hash_login`: `-H LM:NT` keeps only the NT part, and the success line is `{domain}\{user}:{process_secret(self.hash)} {mark_guest()}{mark_pwned()}`. The masked line is `process_secret` with `audit_mode = *` set in `nxc.conf` (`nxc/config.py:55-57`) |
| `nxc-pth-ntds.txt`, `nxc-shares-then-sam.txt`, `nxc-pth-refused.txt` | The same format strings, combined as one log holds them: a pass-the-hash login followed by `--ntds`; a `--shares` run (`smb.py:1752-1761`) then a `--sam` run appended to one file; and a refused hash login, `fail(f"{domain}\\{self.username}:{process_secret(self.hash)} {error} ")` without `--verbose` (`smb.py:614-616`) |

## creds

The files listed here are **synthetic-from-source**: each line is built from the
format string in impacket's published source (`fortra/impacket` master `75938fc`,
`impacket/examples/secretsdump.py`), not captured from a run. Hosts, names and
passwords are invented lab values.

| File | Built from |
|---|---|
| `secretsdump-cleartext.txt` | LSA banner `LOG.info('%s ' % name)` (`:2291`); DefaultPassword `"%s:" % account` + password (`:2316-2331`); `Dumping Domain Credentials` (`:3690`), `Using the DRSUAPI method` (`:3765`), `Kerberos keys grabbed` (`:3948`), `ClearText passwords grabbed` (`:3958`); NTDS cleartext `"%s:CLEARTEXT:%s"` (`:3173`). The `[*]` prefix is `impacket/examples/logger.py:34-38` |
| `secretsdump-autologon-offline.txt` | As above, an offline hive dump: no `getDefaultLoginAccount`, so the DefaultPassword account is `(Unknown User)` (`UNKNOWN_USER`, `:2095`) |

## Tool lines that are not data (synthetic-from-source)

Each line in these files is built from a format string in the tool's source at
the commit named, with invented lab values. The nmap lines were also checked
against a real nmap 7.98 `-v -d` run against localhost (not committed).

| File | Built from |
|---|---|
| `nmap/nmap-verbose-os.nmap` | nmap `f06480d`: timing report `nmap.cc:2050-2057`; `Scanned at` `output.cc:536`; `Final times for host` `output.cc:2416`; `Increasing send delay` `scan_engine.cc:1664`; `giving up on port` `scan_engine.cc:2655`; `Overall sending rates` `scan_engine.cc:110`; `mass_dns:` `libnetutil/massdns.cc:1402`; OS-detection tries `osscan2.cc:3471`; `Timing: About` `timing.cc:726`; `OS:` fingerprint wrapping `osscan.cc:935-960`; `No exact OS matches` `output.cc:1926`; `Read from` `output.cc:2647`; `OS detection performed` `output.cc:2505`; `Raw packets sent` `tcpip.cc:104` |
| `creds/secretsdump-lsa-online.txt` | impacket `75938fc` `secretsdump.py`: `$MACHINE.ACC` with a known machine name prints `DOMAIN\NAME$` Kerberos keys (`:2475`), `plain_password_hex` (`:2378`) and the NT line (`:2367`); a secret with no decoder, such as `NL$KM`, is printed by `hexdump()` (`structure.py:647-667`, rendered here by that function) and then as `name:hex` (`:2408-2414`) |
| `creds/hashcat-session.txt` | hashcat `8e16328` `src/terminal.c`: `starting` `:268`, the status screen labels (`:3772-4654`), `Started:`/`Stopped:` `:295-296` |
| `creds/getnpusers-request.txt` | impacket `examples/GetNPUsers.py`: `printTable` `:52-66` (rendered here by that function), the table then `\n\n\n` `:300-301`, then the `$krb5asrep$` line `:196-198` |
| `netexec/nxc-kali-proxychains.txt` | kali-defaults `3267d7c` `etc/skel/.zshrc:100` (two-line prompt); proxychains-ng `aa87f65` `src/core.c:445,550,562,722` and `main.c:105,136`, `libproxychains.c:145`; NetExec `98a4679` `smb.py:559` (failed login), `connection.py:158` and `logger.py:87-90` (rich handler); rich `9d8f9a3` `traceback.py:662` and `box.py:325` (ROUNDED panel), layout taken from a real render through a pipe |

## Saved the way the capture guide says (synthetic-from-source)

Each file is the shape the tool writes when its output is saved as
`loot/references/capture.md` recommends. The lines are built from the tool's
source at the commit named; RIVERRUN (192.168.56.24), the client
192.168.56.25 and the accounts jojen.reed, meera.reed and osha are invented
GOAD-range values, held by no other fixture.

| File | Built from |
|---|---|
| `netexec/nxc-log-riverrun.log` | NetExec `98a4679`: `--log` header `[%Y-%m-%d %H:%M:%S]> <argv>` and line format `%(asctime)s \| %(filename)s:%(lineno)s - %(levelname)s - %(message)s` (`logger.py:177-199`); every display/success/highlight line goes to it (`logger.py:132-176`); the message is the screen line (`logger.py:111-130`); banner `smb.py:333`, login `smb.py:539`, SAM dump `smb.py:2281,2315,2319` |
| `creds/RIVERRUN_192.168.56.24_2026-10-17_091204.sam` | NetExec `98a4679`: SAM dump file `~/.nxc/logs/sam/<host>_<ip>_<date>.sam` (`connection.py:216-220`), each line secretsdump's `user:rid:lm:nt:::` with no prefix; the same lines as `netexec/nxc-log-riverrun.log` |
| `creds/secretsdump-cached-riverrun.txt` | impacket `75938fc` `secretsdump.py`: cached logon `"%s/%s:$DCC2$%s#%s#%s: (%s)"` with the DNS domain name and a UTC timestamp (`:2262-2269`) |
| `creds/Responder-Session.log` | Responder `424fbe5`: session log `%(asctime)s - %(message)s`, `%m/%d/%Y %I:%M:%S %p` (`settings.py:364`), written by `text()` with colours stripped (`utils.py:104-106`); `Client :`, `Username :` and `Hash :` lines (`utils.py:462-475`), the hash on its own label's line; `Skipping previously captured hash` (`utils.py:490`) |

## Databases (synthetic-from-source)

`tests/databases/` holds SQL, not fixtures: each test builds the database from it,
so no binary file is committed and nothing under `tests/fixtures/` changes. The
`CREATE TABLE` statements are the tables NetExec v1.5.1 (`c7dc286b`) declares,
as SQLAlchemy writes them for SQLite, and those Responder v3.2.2.0 creates. DREADFORT (10.10.10.23), KARHOLD
(10.10.10.24), OLDBOX (192.168.56.31) and the accounts roose.bolton,
ramsay.snow and svc_gpp are invented GOAD-range values, held by no other
fixture; rickon.stark is the account of `netexec/nxc-cred-check.txt`, so the two
can be imported together.

| File | Built from |
|---|---|
| `nxc-smb.sql` | `nxc/protocols/smb/database.py:42-190` (tables); `smb.py:273-283` `add_host` (`signing` is signing required), `:1479` `add_share(self.hostname, …)` (the host name in `hostid`); SAM rows `LM:NT` with the host's name as domain, a pass-the-hash login the NT hash only |
| `nxc-winrm.sql` | `nxc/protocols/winrm/database.py:20-70` |
| `responder.sql` | Responder v3.2.2.0 (`424fbe5`) `utils.py:410-420` `CreateResponderDb` (tables), `:422-450` `SaveToDb` (one row per module, type, client and user; `::ffff:` dropped from the client), `:470-478` (the session log prints `cleartext`, else `fullhash`, else `hash`); meera.reed's row is the capture in `creds/Responder-Session.log`, jojen.reed (192.168.56.26), hodor (192.168.56.27) and gilly are invented |
| `nxc-ldap.sql` | `nxc/protocols/ldap/database.py:19-46`: hosts and users, no relations, so Trove has no reader for it |

## Real captures from the GOAD run of 2026-10-19

Tool output from the logged run in `tests/corpus/SOURCES.md`, with the same
values replaced. Each tests one parser, so it is a fixture, not part of the
corpus engagement.

| File | Command |
|---|---|
| `netexec/nxc-sam-goad.log` | `netexec smb 192.168.56.22 -u goadmin -p 'Wildf1re-Kn0ws' -d north.sevenkingdoms.local --sam --log …/nxc-sam.log --no-progress` |
| `netexec/nxc-failed-login.txt` | `netexec smb 192.168.56.10 -u brandon.stark -p 'NotThePassword1' --no-progress \| tee …` |
| `netexec/nxc-pth-lmnt-refused.txt` | `netexec smb 192.168.56.23 -u goadmin -H '<LM>:<NT>' --local-auth --no-progress \| tee …` (refused: `STATUS_LOGON_FAILURE`) |
| `nmap/nmap-os-verbose.gnmap` | `sudo nmap -sV -O --traceroute -v -oA …/nmap-os-verbose 192.168.56.11 192.168.56.22` (nmap 7.80 exited 139 after writing all three files) |
| `bloodhound/north_default_20261019142903_bloodhound.zip` | `bloodhound-ce-python -d north.sevenkingdoms.local -u brandon.stark -p 'iseedeadpeople' -ns 192.168.56.11 --zip` (default collection: no object properties) |
