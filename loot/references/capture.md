# Saving tool output for Trove

One way to save each tool's output, chosen from the tool's own save options so
Trove reads all of it. Give the user the row for their tool when they ask how to
save output, or when a file of a tool Trove reads went to AI extraction whole.

| Tool | Save it like this | Import |
|---|---|---|
| nmap | `nmap -sC -sV -oA scans/<name> <targets>` | `scans/<name>.xml` |
| masscan | `masscan <targets> -p<ports> --banners -oX scans/<name>.xml` | the `.xml` |
| naabu | `naabu -host <targets> -p - -json -o scans/<name>.json` | the `.json` |
| NetExec | set `log_mode = True` in `~/.nxc/nxc.conf` once, or add `--log nxc/<what>.log` to one run | `~/.nxc/logs/`, or the `.log` |
| NetExec database | make a workspace per engagement first: `nxcdb`, then `workspace create <name>` | `~/.nxc/workspaces/<name>/` |
| secretsdump | `secretsdump.py '<domain>/<user>:<pass>@<ip>' \| tee dumps/secretsdump-<ip>.txt` | the `.txt` |
| GetUserSPNs, GetNPUsers | `GetUserSPNs.py -request -dc-ip <ip> <domain>/<user>:<pass> \| tee roast/spns-<domain>.txt` | the `.txt` |
| hashcat | crack with the potfile on (the default), or `--potfile-path loot.pot` | the potfile, after the dump that holds the hashes |
| Responder | run it as usual | `Responder-Session.log` and `Responder.db` in the `logs/` folder of Responder's install |
| BloodHound | `bloodhound-ce-python -d <domain> -u <user> -p <pass> -ns <dc-ip> -c All --zip` | the `.zip` |
| certipy | `certipy find -u <user>@<domain> -p <pass> -dc-ip <ip> -json -output adcs/<domain>` | `adcs/<domain>_Certipy.json` |

Why these, and what to avoid:

- **NetExec** `log_mode = True` makes every run write the log that `--log`
  writes: every screen line, plain text, plus the command that ran, under
  `~/.nxc/logs/<date>/`. Import the whole `~/.nxc/logs/` folder. Its `sam/`,
  `lsa/` and `ntds/` files hold hashes with no host; each joins the account the
  log names, unless several hosts hold that hash or it is the empty password's.
  A dump file imported without its log stays apart and says so. The log has
  no colour even when NetExec runs in a terminal; a `script` or tmux recording
  of the same run keeps the colour codes, and Trove sends those lines to the AI.
  Table output Trove has no reader for (`--users`, `--loggedon-users`) also goes
  to the AI, line by line.
- **NetExec database**: NetExec also keeps every host, credential, login and
  admin right it finds in `~/.nxc/workspaces/<name>/smb.db` (and `winrm.db`,
  `mssql.db`). Every run goes into the `default` workspace unless another is
  made, so a `default` database can hold hosts and passwords from earlier
  labs; the import counts its hosts by range so that shows. `--lsa` secrets
  are not in the database; import the logs for those. `ldap.db` and `ssh.db`
  are not read.
- **naabu** `-json` writes one line per open port with its protocol; the
  plain `host:port` lines do not say TCP or UDP, so they go to the AI. On
  naabu 2.7 or later `-oX` or `-oG` reads as well; avoid `-csv`. By default it
  scans only the top 100 ports, which miss 5985, 636, 3268 and 9389, hence
  `-p -`. It records no service names unless `-sV` finds nmap's probe file.
  Since 2.3.3 it uses a connect scan; a SYN scan (`-s s`) needs root and falls
  back with `Routing could not be determined` over a lab VPN. Over a VPN, lower
  `-rate` or add `-verify` so dropped probes do not hide open ports.
- **secretsdump** has no save option that records the target, so save the
  screen, with or without `-outputfile`: its `.ntds` file holds the same
  accounts with no domain or host, and its SAM and LSA files lose the sections
  Trove reads. Leave out `-ts` (its timestamps hide them). A SAM dump is tied to its host through the
  dumped machine account's name, so import a scan that names the host too.
- **GetUserSPNs** with `-outputfile` stops printing the hashes, so save the
  screen instead. It asks for RC4 tickets, so AES-only accounts fail with
  `KDC_ERR_ETYPE_NOSUPP` and write nothing; NetExec's `ldap … --kerberoasting
  <file>` gets their `$krb5tgs$18$` hashes.
- **hashcat** potfile lines are `hash:password`; Trove joins each to the account
  whose hash it is. Other `--outfile-format` choices drop the hash or the
  password; `--outfile-format 1,3` writes the password as hex, which cannot be
  told from a hex password.
- **Responder** colours its screen output even when piped; its session log is
  the same lines without colour, with the client's address. It is written in
  the `logs/` folder next to `Responder.py`, not where Responder was run. The per-capture
  `logs/*-NTLMv2-*.txt` files name the client only in the file name. `Responder.db`
  holds the same captures plus any cleartext password, each with its client.
- **BloodHound** needs `-c All` (or at least object properties): without them
  users carry no account name and Trove records none. SharpHound's default zip
  works; do not set `--zippassword`. NetExec's `--bloodhound` defaults to
  `-c Default`, so pass `-c All`.
- **certipy** `find` output reads the same saved with `-json`, `-text`, or
  `-stdout | tee` (with or without `-vulnerable`). Each weakness it flags lands
  on the CA's host, found by the CA's DNS name, so import a scan or NetExec
  output that names that host as well; until then the weaknesses wait.

Getting the run to work (seen in a GOAD lab run):

- Kerberos tools need the domain's name to resolve. Without it they fail with
  `Connection error (<DOMAIN>:88)`, which names neither DNS nor the cause; map
  each domain's FQDN to its DC in `/etc/hosts`, or point DNS at the DC.
- ldapdomaindump and adidnsdump fail with `unsupported hash type MD4` on
  OpenSSL 3 (Ubuntu 22.04 and later): enable OpenSSL's legacy provider.
- The account with RID 500 may be renamed: read the RID in the SAM dump
  (`<name>:500:…`) before passing the hash, rather than trying `Administrator`.
- Leave your own address out of SMB sweeps while Responder runs: its fake SMB
  server answers as an invented Windows host, and Trove records it as one.
- impacket installed with pip or pipx is `secretsdump.py`; Kali's package is
  `impacket-secretsdump`; the rows above use the pip names.
