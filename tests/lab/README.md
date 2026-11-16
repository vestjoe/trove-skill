# Trove test lab

This lab exists so Trove's parsers are tested against what the tools really
write. A fixture built from a tool's source shows what the source says it
prints; a capture from this lab shows what a real run printed. When a parser's
fixtures were built from source, run the tool here, keep the capture under
`tests/samples/`, and add a test that imports it. A capture that does not match
the fixture is a finding: fix the parser or the fixture, and say which in the
pull request. Nothing here runs in CI; the captures it leaves do.

It is a throwaway Docker network of lab hosts, a domain controller and two
tool containers.

```
tests/lab/capture.sh            # scan.sh, then creds.sh
tests/lab/capture.sh creds      # only creds.sh
```

builds the images, starts the lab, runs the scripts, writes every output to
`tests/lab/out/` (ignored by git) and tears the lab down. It needs Docker with
Compose (`docker compose` or `docker-compose`). The first build takes several
minutes: John, Hydra and kerbrute are built from source.

| Host | Address | Services |
|---|---|---|
| lab-web | 10.99.56.10 | ssh 22, ftp 21, telnet 23, smtp 25, http 80 and 8080, https 443; local account `quill` for ssh and ftp |
| lab-files | 10.99.56.11 | smb 139/445, dns 53 (tcp and udp), snmp 161/udp, ntp 123/udp |
| lab-cache | 10.99.56.12 | redis 6379, memcached 11211 (tcp and udp), http 80 and 8080, https 443 |
| lab-dc | 10.99.56.13 | Samba 4.19 domain controller for `arbor.lab.test` (NetBIOS `ARBOR`): Kerberos 88, LDAP 389, SMB 445, DNS 53 |
| creds | 10.99.56.6 | John the Ripper `37bebbe`, Hydra `707c822`, kerbrute `9cfb81e` and v1.0.3, impacket `75938fc`, smbclient |
| scanner | 10.99.56.5 | masscan 1.3.2, naabu 2.7.0, nmap, nuclei 3.11.1 with nuclei-templates v10.5.0; resolves `*.lab.test` through lab-files |

`10.99.56.250` is left unused for masscan's `--source-ip`. The tools in `creds`
are pinned to the commits the fixtures in `tests/SOURCES.md` were built from, so
a capture checks that fixture.

The domain's accounts, all invented: `rowan.ash` and `alder.fern` share the
sprayed password, and `alder.fern` must change it at next logon; `hazel.birch`
does not require Kerberos preauthentication; `willow.reed` and `elm.stone` have
passwords that are in no word list. `dc/start.sh` sets them up.

Two things differ from a Windows domain:

- impacket's `secretsdump` cannot replicate from Samba (`Failed to decode remote
  prefixMap`). `capture.sh` writes `out/arbor.ntds` from the DC's own database
  instead (`dc/lab.py ntds`), in secretsdump's NTDS line format.
- Samba's KDC asks for preauthentication when `krbtgt` requires it, not only the
  account, so `krbtgt` has the no-preauth flag as well.

- **Add a service:** install its package in `target/Dockerfile`, add a case to
  `target/start.sh`, and name it in a host's `SERVICES` in `compose.yaml`.
- **Add a scanner or format:** install it in `scanner/Dockerfile` and add a `run`
  line to `scan.sh`; `run` records the command in `out/commands.txt`.
- **Add a login or cracking tool:** install it in `creds/Dockerfile` and add it
  to `creds.sh`, which records each command in `out/creds-commands.txt`.
- **Use a capture in a test:** copy the file into `tests/fixtures/<tool>/` (imported
  by the end-to-end tests) or `tests/samples/<dir>/` (only by the test that names
  it) and add a row to `tests/SOURCES.md` with the command from the commands file.

Lab addresses, names, accounts, passwords and the self-signed certificate are
synthetic; the captures hold nothing that needs removing before they are committed.
