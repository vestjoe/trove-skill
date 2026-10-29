# Fixture sources

Where the fixtures built from a tool's source, the test databases and the single-parser lab captures came from; the other files under `tests/fixtures/` are earlier tool-output samples and hand-written notes. Each file listed under "Built from source" is written line by line from the format string in the tool's published source, at the commit or file and line named, with invented lab values. Kept outside `tests/fixtures/` because every file there is imported by the end-to-end tests.

## Built from source

| File | Built from |
|---|---|
| `netexec/nxc-sam.txt` | NetExec `89a698d` `smb.py` `sam()`; impacket SAM line `"%s:%d:%s:%s:::"` |
| `netexec/nxc-ntds.txt` | NetExec `smb.py` `ntds()`, `(status=…)` suffix removed; impacket `75938fc` NTDS line `"%s:%s:%s:%s:::"` (`secretsdump.py:3072-3074`) |
| `netexec/nxc-pth.txt` | NetExec `smb.py:572-605` `hash_login` (`-H LM:NT` keeps the NT part); the masked line is `audit_mode = *` (`config.py:55-57`) |
| `netexec/nxc-pth-ntds.txt`, `netexec/nxc-shares-then-sam.txt`, `netexec/nxc-pth-refused.txt` | the same format strings as one log holds them: pass-the-hash then `--ntds`; `--shares` (`smb.py:1752-1761`) then `--sam`; a refused hash login (`smb.py:614-616`) |
| `netexec/nxc-kali-proxychains.txt` | kali-defaults `3267d7c` `.zshrc:100` prompt; proxychains-ng `aa87f65` `core.c`, `main.c`; NetExec `98a4679` `smb.py:559`, `logger.py:87-90`; rich `9d8f9a3` traceback panel |
| `netexec/nxc-log-riverrun.log` | NetExec `98a4679` `--log` header and line format (`logger.py:177-199`); banner `smb.py:333`, login `:539`, SAM dump `:2281-2319` |
| `creds/secretsdump-cleartext.txt` | impacket `75938fc` `secretsdump.py`: LSA banner `:2291`, DefaultPassword `:2316-2331`, NTDS `:CLEARTEXT:` `:3173`; `[*]` prefix `logger.py:34-38` |
| `creds/secretsdump-autologon-offline.txt` | the same, offline: DefaultPassword under `(Unknown User)` (`:2095`) |
| `creds/secretsdump-lsa-online.txt` | impacket `75938fc` `secretsdump.py`: `$MACHINE.ACC` keys `:2475`, `plain_password_hex` `:2378`, NT line `:2367`; `NL$KM` hexdump (`structure.py:647-667`) |
| `creds/secretsdump-cached-riverrun.txt` | impacket `75938fc` cached logon `"%s/%s:$DCC2$%s#%s#%s: (%s)"` (`:2262-2269`) |
| `creds/RIVERRUN_192.168.56.24_2026-10-17_091204.sam` | NetExec `98a4679` SAM dump file (`connection.py:216-220`); the same lines as `nxc-log-riverrun.log` |
| `creds/hashcat-session.txt` | hashcat `8e16328` `terminal.c`: start `:268`, status screen `:3772-4654`, `Started:`/`Stopped:` `:295-296` |
| `creds/getnpusers-request.txt` | impacket `GetNPUsers.py` `printTable` `:52-66`, then the `$krb5asrep$` line `:196-198` |
| `creds/Responder-Session.log` | Responder `424fbe5` session log format (`settings.py:364`, `utils.py:104-106`); `Client :`, `Username :`, `Hash :` (`utils.py:462-475`) |
| `nmap/naabu-basic.xml`, `nmap/naabu-basic.gnmap` | naabu v2.7.0 `pkg/runner/output_nmap.go`: `writeNmapXML` (`xml.Header`, `<!DOCTYPE nmaprun>`, two-space indent, state `open`) and `writeGreppable` (`# Naabu %s scan initiated`, `Host: %s (%s)\tPorts:`, `%d/open/%s//%s//%s/`, `# Naabu done at`) |
| `naabu/naabu-sunspear.json` | naabu v2.3.0 `v2/pkg/runner/output.go` `jsonResult` (embedded `Result` then `port`, `protocol`, `tls`; `host` only when it differs from `ip`) |
| `naabu/naabu-pyke-sv.json` | naabu v2.7.0 `pkg/runner/output.go` `jsonResult` with `-sV` service fields (`pkg/port/port.go` `Service`), written to the `-o` file |
| `nmap/masscan-basic.xml` | masscan `8e6b3b0` `out-xml.c`: `xml_out_open`, `xml_out_status`, `xml_out_banner` (a banner is its own `<host>`), `xml_out_close`; `\r\n` line ends |
| `nmap/masscan-basic.gnmap` | masscan `8e6b3b0` `out-grepable.c`: `Timestamp: %llu\tHost: %s ()\tPorts: …` with the service from `tcp_service_name(port)`, banner line `Host: %s ()\tPort: %u\tService: %s\tBanner: %s` |
| `masscan/masscan-list.txt`, `masscan/masscan.json`, `masscan/masscan.ndjson`, `masscan/masscan-screen.txt` | masscan `8e6b3b0` `out-text.c` (`-oL`), `out-json.c` (`-oJ`, `,` line before every record but the first), `out-ndjson.c` (`-oD`), `output.c` `output_report_status`/`output_report_banner` (screen, padded to 79 columns, ARP with MAC and vendor); banner escaping `\xNN` / `\u00NN`; the same scan as `nmap/masscan-basic.*` |
| `nmap/nmap-verbose-os.nmap` | nmap `f06480d` `-v -d` lines (`nmap.cc`, `output.cc`, `scan_engine.cc`, `osscan.cc`, `timing.cc`, `tcpip.cc`), checked against a real nmap 7.98 run |

192.168.56.50, .51, .53 and 2001:db8:5eed::52 (masscan), OLDTOWN (192.168.56.40), SUNSPEAR (192.168.56.43, 2001:db8:5eed::43), PYKE (192.168.56.45), 192.168.56.41, .42 and .44, RIVERRUN (192.168.56.24), 192.168.56.25 and the accounts jojen.reed, meera.reed and osha are invented and held by no other fixture.

## Databases

`tests/databases/` holds SQL that each test turns into a database, so no binary is committed. The tables are those NetExec v1.5.1 (`c7dc286b`) and Responder v3.2.2.0 (`424fbe5`) create. DREADFORT (10.10.10.23), KARHOLD (10.10.10.24), OLDBOX (192.168.56.31) and the accounts roose.bolton, ramsay.snow, svc_gpp, hodor and gilly are invented; rickon.stark matches `netexec/nxc-cred-check.txt` so the two import together.

| File | Built from |
|---|---|
| `nxc-smb.sql` | `nxc/protocols/smb/database.py:42-190`; `smb.py:273-283` `add_host`, `:1479` `add_share` |
| `nxc-winrm.sql` | `nxc/protocols/winrm/database.py:20-70` |
| `nxc-ldap.sql` | `nxc/protocols/ldap/database.py:19-46` (no relations, so Trove has no reader for it) |
| `responder.sql` | Responder `utils.py:410-450` (`CreateResponderDb`, `SaveToDb`); meera.reed's row is the capture in `creds/Responder-Session.log` |

## Single-parser captures

Real output from run 2 in `tests/corpus/SOURCES.md`, with the same values replaced.

| File | Command |
|---|---|
| `netexec/nxc-sam-goad.log` | `netexec smb 192.168.56.22 -u goadmin -p … -d north.sevenkingdoms.local --sam --log …` |
| `netexec/nxc-failed-login.txt` | `netexec smb 192.168.56.10 -u brandon.stark -p 'NotThePassword1'` |
| `netexec/nxc-pth-lmnt-refused.txt` | `netexec smb 192.168.56.23 -u goadmin -H '<LM>:<NT>' --local-auth` (refused) |
| `nmap/nmap-os-verbose.gnmap` | `nmap -sV -O --traceroute -v -oA … 192.168.56.11 192.168.56.22` (nmap 7.80 crashed after writing all three files) |
| `bloodhound/north_default_20261019142903_bloodhound.zip` | `bloodhound-ce-python -d north.sevenkingdoms.local -u brandon.stark -p … -ns 192.168.56.11 --zip` (default collection: no object properties) |
