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
| [hashcat](#hashcat) | crack with the potfile on (the default), or `--potfile-path loot.pot` | the potfile |
| [John the Ripper](#john-the-ripper) | `john --show --format=<format> <hashfile> > john/show-<name>.txt` | the `.txt` and the hash file |
| [Hydra](#hydra) | `hydra -L users.txt -P passwords.txt -o hydra/<ip>-<service>.txt <service>://<ip>` | the `.txt` |
| [kerbrute](#kerbrute) | `kerbrute passwordspray -d <domain> --dc <dc-ip> users.txt '<password>' \| tee kerbrute/spray-<domain>.txt` | the `.txt` |
| [Responder](#responder) | run it as usual | `Responder-Session.log` and `Responder.db` in the `logs/` folder of Responder's install |
| [BloodHound](#bloodhound) | `bloodhound-ce-python -d <domain> -u <user> -p <pass> -ns <dc-ip> -c All --zip` | the `.zip` |
| [certipy](#certipy) | `certipy find -u <user>@<domain> -p <pass> -dc-ip <ip> -json -output adcs/<domain>` | `adcs/<domain>_Certipy.json` |

Also read: [user lists](#user-lists) with `--tool users`, and [zip archives](#zip-archives) of any of these. The agent reads anything else, as [How Trove works](how-it-works.md) explains.

## nmap

**Reads:** XML (`-oX`), normal (`-oN`) and grepable (`-oG`) output.

**Records:** hosts and services.

**Save:** `-oA` writes all three. Import the `.xml`.

## masscan

**Reads:** `-oX`, `-oG`, `-oL`, `-oJ`, `-oD` and the screen.

**Records:** each open port is a service with its state. An ARP reply is a host that is up, with its MAC. The first banner for a port is its `banner`, and Trove keeps every banner on the port. masscan's banner type (`title`, `X509`) is not a service name.

**Save:** masscan has no default ports, so give `-p`. `--banners` needs `--source-ip` set to an unused address in the lab range (or a firewall rule dropping `--source-port`'s replies). Otherwise the OS resets the connection before a banner comes back. masscan needs root. Its default rate is 100 packets a second, so raise `--rate` carefully over a VPN.

**Not read:** `-oB` binary output. Convert it with `masscan --readscan <file> -oX <name>.xml`. Trove reads screen output as masscan's only when no nmap line is in the file, because `nmap -v` prints the same `Discovered open port` lines.

## naabu

**Reads:** `-json`, and on naabu 2.7 or later `-oX` and `-oG`.

**Records:** each open port is a service with its protocol, plus name, product, version and banner when service discovery ran. naabu's `-json` output gives no port state, so Trove sets none from it. Its `-oX` and `-oG` output say `open`, and Trove keeps that.

**Save:** use `-p -`, because by default naabu scans only the top 100 ports, which miss 5985, 636, 3268 and 9389. It records no service names unless `-sV` finds nmap's probe file. Add `-r <lab-dns-ip>` when you scan by name, because naabu otherwise uses public resolvers. Lower `-rate` or add `-verify` over a VPN, so dropped probes do not hide open ports.

**Not read:** plain `host:port` lines go to the agent, because they don't say TCP or UDP. Avoid `-csv`.

**In the lab:** since 2.3.3 naabu uses a connect scan. A SYN scan (`-s s`) needs root and falls back with `Routing could not be determined` over a lab VPN. Its UDP scan (`-p u:53`) found nothing in a test lab where `nmap -sU` found DNS and SNMP.

## nuclei

**Reads:** `-j` JSONL, a `-je` JSON export, and `-o` or screen text saved with `-nc`.

**Records:** each result is a `confirmed` finding titled `<template-id>[:<matcher>] at <matched-at>`, on its host when it names one. A `dns` result has no host. An `http`, `ssl` or `tcp` result with a port also makes a service on that port. Trove keeps nuclei's severity, tags, references, CVE and CWE ids and CVSS score as nuclei's, and never assigns a severity of its own.

**Save:** `-j -o` writes one JSON line per result with the address nuclei reached. `-o` text and the screen name no address when the target was a name, so those results wait until a scan names that host. Save the screen with `-nc`, since coloured lines go to the agent. `-or` leaves out each request and response, which Trove does not read, and makes the file much smaller. Add `-ni` in a lab without internet: its out-of-band checks call public servers. Lower `-rl` over a VPN (150 requests a second by default). Update templates with `nuclei -ut` before the run starts.

**Not read:** `-me` markdown and `-se` SARIF exports. `-ms` failed results make no finding. A default-login result becomes a finding and makes no credential.

## NetExec

**Reads:** screen output and `--log` files.

**Records:**

- a login is a credential, with the hosts it worked on and the hosts where it was admin; a 32-hex secret is a pass-the-hash NT hash;
- host flags `signing:False`, `SMBv1:True`, `Null Auth:True` and `DC:True` are findings on that host;
- an empty-password login makes a finding and no credential, and a login with no user is a null-session finding;
- `--sam` and `--ntds` dumps, each tied to the line's host;
- from `--lsa`, cached logons tied to the line's host and machine Kerberos keys with no host; the machine NT hash, DPAPI keys and service passwords go to the agent;
- shares, password policy and `Error <operation>` lines.

A `(Guest)` login proves nothing about the account and makes no credential. A failed login and a secret that `audit_mode` masks as `********` make no credential either. The import report says how many of each there were.

A `--log` file opens with the command that ran. When the log has a login line, Trove keeps that command line from the agent and the import report says so: the login line already shows the account and password typed on it and whether they worked. A login that worked is a credential, and a refused one is not that account's password. When no login line exists, for example when every connection failed, the command line goes to the agent as the only place the password appears.

**Save:** `log_mode = True` makes every run write the log that `--log` writes, under `~/.nxc/logs/<date>/`: every screen line, plain text, plus the command that ran. Import the whole `~/.nxc/logs/` folder. Its `sam/` and `ntds/` files hold hashes with no domain or host. Each joins the account the log names, unless several hosts hold that hash or it is the empty password's. Its `lsa/` files name the domain but no host, and a service password in them goes to the agent. A dump file imported without its log stays apart and says so.

**Not read:** a `script` or tmux recording keeps colour codes, and Trove sends those lines to the agent. The log has no colour codes. Table output Trove has no reader for (`--users`, `--loggedon-users`) also goes to the agent, line by line.

## NetExec database

**Reads:** `smb.db`, `winrm.db` and `mssql.db` in a workspace.

**Records:** hosts (SMB signing off and SMBv1 are findings), credentials, the hosts each one logged in to or was admin on, and shares. A row with an empty password makes nothing. The import report counts the rows in the `groups`, `dpapi_secrets` and `conf_checks_results` tables, which Trove doesn't read, and the hosts per /24.

**Save:** make a workspace per engagement. NetExec puts every run in the `default` workspace unless you make another, so a `default` database can hold hosts and passwords from earlier labs. The per-/24 count shows that.

**Not read:** The database holds no `--lsa` secrets. Import the logs for those. `ldap.db` and `ssh.db` are not read. NetExec writes a login row before it learns of a guest fallback, so only the screen's `(Guest)` tells them apart. Import the logs as well.

## secretsdump

**Reads:** the screen output, also as printed inside NetExec's `--sam` and `--ntds`. For `--lsa` inside NetExec, see [NetExec](#netexec).

**Records:** NT hashes, Kerberos keys (joined to the account's hash), NTDS cleartext passwords, LSA secrets (`_SC_` service passwords and `DefaultPassword`) and cached logons as DCC2 hashes, each tied to its account. Trove ties a SAM dump's accounts to the host through the dumped machine account's name.

**Save:** secretsdump has no save option that records the target, so save the screen with `tee`, with or without `-outputfile`. Its `.ntds` file holds the same accounts with no domain or host, and its SAM and LSA files lose the sections Trove reads. Leave out `-ts`, because its timestamps hide those sections from Trove. Import a scan that names the host too, or the SAM dump waits.

## GetUserSPNs and GetNPUsers

**Reads:** the screen output.

**Records:** kerberoast and AS-REP hashes, and each account's `MemberOf` as group membership, even when every request failed.

**Save:** save the screen. GetUserSPNs stops printing the hashes when you give it `-outputfile`. It asks for RC4 tickets, so AES-only accounts fail with `KDC_ERR_ETYPE_NOSUPP` and write nothing. NetExec's `ldap … --kerberoasting <file>` gets their `$krb5tgs$18$` hashes.

## hashcat

**Reads:** potfiles and outfiles.

**Records:** each cracked password, joined to the account whose hash it cracks.

**Save:** potfile lines are `hash:password`. Import the potfile before or after the dump that holds the hashes. A crack whose hash Trove doesn't hold yet waits, and lands when the dump arrives. Other `--outfile-format` choices drop the hash or the password. `--outfile-format 1,3` writes the password as hex, and nothing tells that apart from a password that is itself hex.

## John the Ripper

**Reads:** `john --show` output.

**Records:** each cracked password, joined to the account whose hash John cracked.

**Save:** run `john --show --format=<format> <hashfile> > john/show-<name>.txt` and import that file and the hash file, in either order. A crack whose hash Trove doesn't hold yet waits, and lands when the hash file arrives.

John prints the password in place of the hash, so Trove joins only the lines that still say whose hash it was:

- A secretsdump or NetExec dump line (`DOMAIN\user:rid:lm:nt:::`) keeps its NT hash. Crack it with `--format=NT`. John prints the same line when it cracks the LM hash, which upper-cases the password, so Trove skips a line whose LM column isn't blank.
- A Responder NetNTLM hash keeps every part but the empty field, so Trove rebuilds it.
- An AS-REP hash keeps `user@REALM`, so Trove fills that account's AS-REP credential.

Trove doesn't read these lines. Import something else instead:

- `user:password` comes from a `user:nthash` file. Give John the dump line as secretsdump wrote it, so the hash stays on the line.
- `?:password` comes from kerberoast tickets and from hashes on a line of their own. Crack them with hashcat and import the potfile.
- `--show=left` lists the hashes John hasn't cracked. Import the hash file itself.

## Responder

**Reads:** `Responder-Session.log` and `Responder.db`.

**Records:** NetNTLM hashes from the session log and `Responder.db`, and cleartext passwords from `Responder.db`, each tied to the client host. The log and the database give one credential per capture.

**Save:** Responder writes both in the `logs/` folder next to `Responder.py`, whatever directory you run it from. It colours its screen even when piped. The session log is the same lines without colour, with the client's address.

**Not read:** the client in a per-capture `logs/*-NTLMv2-*.txt` file, which only the file name gives. Trove reads the hashes in those files with no client host, so import the session log or `Responder.db` for the host.

## Hydra

**Reads:** the `-o` file, as text or with `-b json`, and the screen, with or without colour.

**Records:** each found line is a `confirmed` credential with the host it worked on, plus that host and a service on the port, named after the Hydra module unless a scan already named it. Hydra writes no domain. To give the logins one, add `--tool hydra --realm <domain>`, as for [user lists](#user-lists).

**Save:** `-o` keeps only the found lines, after a header with the command that ran. Give the target as an IP address. Hydra writes the target as you typed it, so a login against a name joins only a host that a scan already holds under that name. Until such a scan is imported, the credential has no host, and the file waits.

**Not read:** when Hydra prints several passwords for one login on one host and port, Trove makes no credential for that login and the import report names it. A wrong failure string in `http-post-form`, or a server that takes any password, makes Hydra print a found line for every password a task was trying. A found line with no login (VNC, Redis, SNMP) or no password makes only the host and service. When the file has a found line, the header's command line doesn't go to the agent. Hydra's own lines (`[DATA]`, `[STATUS]`, `[ATTEMPT]` and the rest) never go to the agent.

## kerbrute

**Reads:** the screen, saved with `tee`, with or without colour, and the `-o` file, from `userenum`, `passwordspray`, `bruteuser` and `bruteforce`.

**Records:** each `VALID LOGIN` line is a `confirmed` credential, and each `VALID USERNAME` line is an account. So is an account `userenum` reports with `KDC_ERR_KEY_EXPIRED`: it exists, but its password has expired, and the import report names it. kerbrute writes them as `user@domain`, so they join the same account from NetExec or BloodHound. A `VALID LOGIN WITH ERROR` line means the password was right but the domain controller refused a ticket, because the password has expired or the clocks differ. Trove stores it as `confirmed` too, and the import report names the account and the reason. An AS-REP hash that `userenum` prints for an account without pre-authentication becomes the same credential as the hash from GetNPUsers.

**Save:** save the screen with `tee`. kerbrute builds from source after v1.0.3 leave the `-o` file empty. The v1.0.3 release writes every line to it.

**Not read:** the domain controllers in the `Using KDC(s):` list. A Kerberos login holds for the whole domain, so Trove gives kerbrute's logins no host. kerbrute's own lines (the banner, the KDC list, `Done! Tested …`, failures with `-v`) never go to the agent.

## BloodHound

**Reads:** collector JSON, or its zip.

**Records:** accounts, groups, computers, memberships, passwords stated in descriptions, and a finding per enabled account open to a roast (no pre-auth, or an SPN). A computer's OS goes on the held host with that full name.

**Save:** collect with `-c All` (or at least object properties). Without them, users carry no account name and Trove records none. SharpHound's default zip works. Do not set `--zippassword`. NetExec's `--bloodhound` defaults to `-c Default`, so pass `-c All`.

**Not read:** domains, OUs, GPOs, containers, trusts, delegation and ACLs. The import report counts the objects in each collector file it doesn't read, and the access rules in the users, groups and computers files.

## certipy

**Reads:** `find` output saved with `-json`, `-text` or `-stdout | tee`, with or without `-vulnerable`.

**Records:** a `confirmed` finding per flagged weakness (`ESC8: <CA>`, `ESC1: template <name> on <CA>`) on the CA's host, which Trove finds by the CA's DNS name. Import a scan or NetExec output that names that host as well. Until then the weaknesses wait. Trove reports a CA name that several hosts carry and records nothing for it.

**Not read:** `req` and `auth` output, and certipy's BloodHound zip.

## User lists

**Reads:** a plain list of usernames, one per line, only with `--tool users`.

**Save:** give the domain the names belong to with `--realm`:

```
loot import users.txt --tool users --realm north.sevenkingdoms.local
```

**Records:** one principal per name. Trove skips blank lines and `#` comments, and keeps a repeated name once. With `--realm`, each bare name gets that domain, shown as `[you, --realm]`, and joins the same account from NetExec or BloodHound. A name written `NORTH\hodor` or `hodor@north.sevenkingdoms.local` keeps its own domain. Without `--realm`, a bare name has no domain and stays a separate account.

Trove refuses `--realm` without `--tool users` or `--tool hydra`. A SAM dump with no `$MACHINE.ACC` section holds local accounts, and a domain would turn them into domain accounts.

## Zip archives

Trove imports each member on its own. It refuses a nested archive, an encrypted or unreadable member, and an archive past 10,000 members, 512 MB per member or 2 GB in total. The import report names each one.

## Getting the run to work

These problems came up in a GOAD lab run:

- Kerberos tools need the domain's name to resolve. Map each domain's FQDN to its DC in `/etc/hosts`, or point DNS at the DC. Otherwise they fail with `Connection error (<DOMAIN>:88)`, which names neither DNS nor the cause.
- ldapdomaindump and adidnsdump fail with `unsupported hash type MD4` on OpenSSL 3 (Ubuntu 22.04 and later): enable OpenSSL's legacy provider.
- Someone may have renamed the account with RID 500. Read the RID in the SAM dump (`<name>:500:…`) before passing the hash, rather than trying `Administrator`.
- Leave your own address out of SMB sweeps while Responder runs: its fake SMB server answers as an invented Windows host, and Trove records it as one.
- impacket installed with pip or pipx is `secretsdump.py`, and Kali's package is `impacket-secretsdump`. The commands above use the pip names.
