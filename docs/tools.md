# Tools Trove reads

How you save a tool's output changes what Trove can read. Each section below gives the formats Trove reads, one way to save the output (chosen from the tool's own save options), the records it produces and what it leaves out. The skill gives the agent the same advice, from [capture.md](https://github.com/vestjoe/trove-skill/blob/main/loot/references/capture.md).

| Tool | Save it like this | Import |
|---|---|---|
| [nmap](#nmap) | `nmap -sC -sV -oA scans/<name> <targets>` | `scans/<name>.xml` |
| [masscan](#masscan) | `sudo masscan <targets> -p1-65535 --banners --source-ip <unused-ip> -oX scans/<name>.xml` | the `.xml` |
| [naabu](#naabu) | `naabu -host <targets> -p - -json -o scans/<name>.json` | the `.json` |
| [nuclei](#nuclei) | `nuclei -l targets.txt -j -o scans/<name>.jsonl` | the `.jsonl` |
| [NetExec](#netexec) | set `log_mode = True` in `~/.nxc/nxc.conf` once, or add `--log nxc/<what>.log` to one run | `~/.nxc/logs/`, or the `.log` |
| [NetExec database](#netexec-database) | make a workspace per engagement first: `nxcdb`, then `workspace create <name>` | `~/.nxc/workspaces/<name>/` |
| [secretsdump](#secretsdump) | `secretsdump.py '<domain>/<user>:<pass>@<ip>' \| tee dumps/secretsdump-<ip>.txt` | the `.txt` |
| [GetUserSPNs, GetNPUsers](#getuserspns-and-getnpusers) | `GetUserSPNs.py -request -dc-ip <ip> <domain>/<user>:<pass> \| tee roast/spns-<domain>.txt` | the `.txt` |
| [hashcat](#hashcat) | crack with the potfile on (the default), or `--potfile-path loot.pot` | the potfile, after the dump that holds the hashes |
| [Responder](#responder) | run it as usual | `Responder-Session.log` and `Responder.db` in the `logs/` folder of Responder's install |
| [BloodHound](#bloodhound) | `bloodhound-ce-python -d <domain> -u <user> -p <pass> -ns <dc-ip> -c All --zip` | the `.zip` |
| [certipy](#certipy) | `certipy find -u <user>@<domain> -p <pass> -dc-ip <ip> -json -output adcs/<domain>` | `adcs/<domain>_Certipy.json` |

Also read: [user lists](#user-lists) with `--tool users`, and [zip archives](#zip-archives) of any of these. Anything else is read by the agent; see [How Trove works](how-it-works.md).

## nmap

**Reads:** XML (`-oX`), normal (`-oN`) and grepable (`-oG`) output.

**Records:** hosts and services.

**Save:** `-oA` writes all three; import the `.xml`.

## masscan

**Reads:** `-oX`, `-oG`, `-oL`, `-oJ`, `-oD` and the screen.

**Records:** each open port is a service with its state; an ARP reply is a host that is up, with its MAC. The first banner for a port is its `banner`, and every banner is kept on the port. masscan's banner type (`title`, `X509`) is not a service name.

**Save:** masscan has no default ports, so give `-p`. `--banners` needs `--source-ip` set to an unused address in the lab range (or a firewall rule dropping `--source-port`'s replies); otherwise the OS resets the connection before a banner comes back. It needs root. Its default rate is 100 packets a second; raise `--rate` carefully over a VPN.

**Not read:** `-oB` binary output. Convert it with `masscan --readscan <file> -oX <name>.xml`. Screen output is read as masscan's only when no nmap line is in the file, since `nmap -v` prints the same `Discovered open port` lines.

## naabu

**Reads:** `-json`, and on naabu 2.7 or later `-oX` and `-oG`.

**Records:** each open port is a service with its protocol, plus name, product, version and banner when service discovery ran. naabu writes no state, so none is set.

**Save:** by default naabu scans only the top 100 ports, which miss 5985, 636, 3268 and 9389, hence `-p -`. It records no service names unless `-sV` finds nmap's probe file. Scanning by name, it uses public resolvers: add `-r <lab-dns-ip>`. Over a VPN, lower `-rate` or add `-verify` so dropped probes do not hide open ports.

**Not read:** plain `host:port` lines go to the agent, because they don't say TCP or UDP. Avoid `-csv`.

**In the lab:** since 2.3.3 naabu uses a connect scan; a SYN scan (`-s s`) needs root and falls back with `Routing could not be determined` over a lab VPN. Its UDP scan (`-p u:53`) found nothing in a test lab where `nmap -sU` found DNS and SNMP.

## nuclei

**Reads:** `-j` JSONL, a `-je` JSON export, and `-o` or screen text saved with `-nc`.

**Records:** each result is a `confirmed` finding titled `<template-id>[:<matcher>] at <matched-at>`, on its host. An `http`, `ssl` or `tcp` result with a port also makes a service on that port. nuclei's severity, tags, references, CVE and CWE ids and CVSS score are kept as nuclei's; Trove never assigns a severity of its own.

**Save:** `-j -o` writes one JSON line per result with the address nuclei reached. `-o` text and the screen name no address when the target was a name, so those results wait until a scan names that host. Save the screen with `-nc`, since coloured lines go to the agent. `-or` leaves out each request and response, making the file much smaller; Trove does not read them. Add `-ni` in a lab without internet: its out-of-band checks call public servers. Over a VPN, lower `-rl` (150 requests a second by default). Update templates with `nuclei -ut` before the run, not during it.

**Not read:** `-me` markdown and `-se` SARIF exports. `-ms` failed results make no finding. Default-login results are findings, not credentials.

## NetExec

**Reads:** screen output and `--log` files.

**Records:**

- a login is a credential, with the hosts it worked on and the hosts where it was admin; a 32-hex secret is a pass-the-hash NT hash;
- host flags `signing:False`, `SMBv1:True`, `Null Auth:True` and `DC:True` are findings on that host;
- an empty-password login is a finding, not a credential, and a login with no user is a null-session finding;
- `--sam`, `--ntds` and `--lsa` dumps, each tied to the line's host;
- shares, password policy and `Error <operation>` lines.

A `(Guest)` login proves nothing about the account and makes no credential. Neither does a failed login, nor a secret masked as `********` by `audit_mode`; the import report says how many of each there were.

**Save:** `log_mode = True` makes every run write the log that `--log` writes, under `~/.nxc/logs/<date>/`: every screen line, plain text, plus the command that ran. Import the whole `~/.nxc/logs/` folder. Its `sam/`, `lsa/` and `ntds/` files hold hashes with no host; each joins the account the log names, unless several hosts hold that hash or it is the empty password's. A dump file imported without its log stays apart and says so.

**Not read:** a `script` or tmux recording keeps colour codes, and Trove sends those lines to the agent; the log has none. Table output Trove has no reader for (`--users`, `--loggedon-users`) also goes to the agent, line by line.

## NetExec database

**Reads:** `smb.db`, `winrm.db` and `mssql.db` in a workspace.

**Records:** hosts (SMB signing off and SMBv1 are findings), credentials, the hosts each one logged in to or was admin on, and shares. A row with an empty password makes nothing. Other tables are counted in the import report, as are hosts per /24.

**Save:** every run goes into the `default` workspace unless another is made, so a `default` database can hold hosts and passwords from earlier labs; the per-/24 count shows that. Make a workspace per engagement.

**Not read:** `--lsa` secrets are not in the database; import the logs for those. `ldap.db` and `ssh.db` are not read. NetExec writes a login row before it learns of a guest fallback, so only the screen's `(Guest)` tells them apart; import the logs as well.

## secretsdump

**Reads:** the screen output, also as printed inside NetExec's `--sam`, `--ntds` and `--lsa`.

**Records:** NT hashes, Kerberos keys (joined to the account's hash), NTDS cleartext passwords, LSA secrets (`_SC_` service passwords and `DefaultPassword`) and cached logons as DCC2 hashes, each tied to its account. A SAM dump's accounts are tied to the host through the dumped machine account's name.

**Save:** secretsdump has no save option that records the target, so save the screen with `tee`, with or without `-outputfile`. Its `.ntds` file holds the same accounts with no domain or host, and its SAM and LSA files lose the sections Trove reads. Leave out `-ts`: its timestamps hide them. Import a scan that names the host too, or the SAM dump waits.

## GetUserSPNs and GetNPUsers

**Reads:** the screen output.

**Records:** kerberoast and AS-REP hashes, and each account's `MemberOf` as group membership, even when every request failed.

**Save:** with `-outputfile`, GetUserSPNs stops printing the hashes, so save the screen instead. It asks for RC4 tickets, so AES-only accounts fail with `KDC_ERR_ETYPE_NOSUPP` and write nothing; NetExec's `ldap … --kerberoasting <file>` gets their `$krb5tgs$18$` hashes.

## hashcat

**Reads:** potfiles and outfiles.

**Records:** each cracked password, joined to the account whose hash it cracks.

**Save:** potfile lines are `hash:password`. Import the potfile after the dump that holds the hashes. Other `--outfile-format` choices drop the hash or the password; `--outfile-format 1,3` writes the password as hex, which cannot be told from a hex password.

## Responder

**Reads:** `Responder-Session.log` and `Responder.db`.

**Records:** captured NetNTLM hashes and cleartext passwords, each tied to the client host. The log and the database give one credential per capture.

**Save:** both are written in the `logs/` folder next to `Responder.py`, not where Responder was run. Responder colours its screen even when piped; the session log is the same lines without colour, with the client's address.

**Not read:** the per-capture `logs/*-NTLMv2-*.txt` files name the client only in the file name.

## BloodHound

**Reads:** collector JSON, or its zip.

**Records:** accounts, groups, computers, memberships, passwords stated in descriptions, and a finding per enabled account open to a roast (no pre-auth, or an SPN). A computer's OS goes on the held host with that full name.

**Save:** collect with `-c All` (or at least object properties); without them users carry no account name and Trove records none. SharpHound's default zip works; do not set `--zippassword`. NetExec's `--bloodhound` defaults to `-c Default`, so pass `-c All`.

**Not read:** OUs, GPOs, trusts, delegation, containers and ACLs are counted in the import report, not recorded.

## certipy

**Reads:** `find` output saved with `-json`, `-text` or `-stdout | tee`, with or without `-vulnerable`.

**Records:** a `confirmed` finding per flagged weakness (`ESC8: <CA>`, `ESC1: template <name> on <CA>`) on the CA's host, found by its DNS name. Import a scan or NetExec output that names that host as well; until then the weaknesses wait. A CA name several hosts carry is reported, not recorded.

**Not read:** `req` and `auth` output, and certipy's BloodHound zip.

## User lists

**Reads:** a plain list of usernames, one per line, only with `--tool users`.

**Records:** one credential per line with only the account name.

## Zip archives

Each member is imported on its own. A nested archive, an encrypted or unreadable member, or an archive past 10,000 members, 512 MB per member or 2 GB in total is refused by name.

## Getting the run to work

Seen in a GOAD lab run:

- Kerberos tools need the domain's name to resolve. Without it they fail with `Connection error (<DOMAIN>:88)`, which names neither DNS nor the cause; map each domain's FQDN to its DC in `/etc/hosts`, or point DNS at the DC.
- ldapdomaindump and adidnsdump fail with `unsupported hash type MD4` on OpenSSL 3 (Ubuntu 22.04 and later): enable OpenSSL's legacy provider.
- The account with RID 500 may be renamed: read the RID in the SAM dump (`<name>:500:…`) before passing the hash, rather than trying `Administrator`.
- Leave your own address out of SMB sweeps while Responder runs: its fake SMB server answers as an invented Windows host, and Trove records it as one.
- impacket installed with pip or pipx is `secretsdump.py`; Kali's package is `impacket-secretsdump`. The commands above use the pip names.
