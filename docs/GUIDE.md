# Trove user guide

This guide covers how Trove works, the commands, the tools it reads, and a walkthrough on a GOAD lab. To install it, see the [README](../README.md).

## Contents

- [How it works](#how-it-works)
- [Commands](#commands)
- [Tools Trove reads](#tools-trove-reads)
- [Walkthrough: castelblack](#walkthrough-castelblack)
- [Searching](#searching)
- [Notes and finding status](#notes-and-finding-status)
- [Troubleshooting](#troubleshooting)

## How it works

**One engagement is one directory.** `/loot-init htb-forest` creates `htb-forest.loot/` in the current directory. Every command uses the nearest `<name>.loot/` at or above the directory you started OpenCode or Claude Code in. To pick a different one, name it in your request ("in the forest engagement…") or start the tool from that engagement's directory.

**Every file you import is kept as it is.** Trove stores the bytes verbatim under `raw/`, including files nothing could read. Importing the same file twice changes nothing.

**Records are built from those files.** A record is a host, service, credential, principal, group, share, finding or note. Records from different files merge: a host from an nmap scan and the same host from NetExec output are one record that cites both.

**Every value says where it came from.** Each field shows its origin, the file it came from and, where it matters, the exact text quoted from that file:

```
state       confirmed   [tool, nxc-cred-check.txt, quote "[+] north.sevenkingdoms.local\rickon.stark:Winter2022"]
```

| Origin | Meaning |
|---|---|
| `tool` | A parser read it from a tool's output. |
| `ai` | The agent read it from a file no parser handles, and its quote was found in that file. |
| `you` | You wrote it: a note, or a finding status you set. |

**The agent reads what parsers can't.** Notes, scratch logs and output from tools Trove has no parser for are read by the agent, which proposes records. Each proposed value must quote the file word for word. A value is dropped if its quote isn't in the file, or if the value isn't in its own quote. The import report says what was kept and what was dropped.

**Imported text is data.** A file can contain text written to steer an AI. Trove treats everything it imports as data, never as instructions.

## Commands

| Command | Does |
|---|---|
| `/loot-init <name>` | Create `<name>.loot/` in the current directory. |
| `/loot-import <path>` | Import a file, a directory or `-` for stdin, then have the agent extract records from anything no parser read. |
| `/loot-find <search>` | Search records. Accepts plain words or `--type` and `--where` (see [Searching](#searching)). |
| `/loot-chat <question>` | Ask a question. The answer lists what the records say, each fact cited by record id, then any suggestions, labelled as not from the data. |
| `/loot-note <text>` | Save a note. Add `--host <ip or name>` to tie it to a host, and `--tag <tag>` (repeatable) to tag it. |

`/loot-import` options:

- `--tool <name>` forces a parser instead of detecting the format, for example `--tool users` for a plain list of usernames.
- `--no-ai` stores and parses the files but leaves anything unparsed for later.

You don't have to use the commands. The skill also works from plain requests, such as "import scans/full.xml" or "what do I have on 10.10.10.5?". Ask "what does this engagement hold?" to get the number of records of each type and any files still waiting for AI extraction.

## Tools Trove reads

| Tool | What becomes records |
|---|---|
| nmap (XML, normal, grepable) | Hosts and services. |
| masscan (`-oX`, `-oG`, `-oL`, `-oJ`, `-oD`, screen) | Hosts and open ports as services, with their banners. |
| naabu (`-json`, and `-oX`/`-oG` from 2.7) | Hosts and open ports as services. |
| nuclei (`-j`, `-je`, `-o`, screen with `-nc`) | Each result as a finding on its host and port, with nuclei's severity kept as nuclei's. |
| NetExec screen output and `--log` files | Logins as credentials, with the hosts they worked on and where they were admin; host flags such as SMB signing off, SMBv1 and null auth as findings; shares; password policy; SAM, LSA and NTDS dumps. |
| NetExec workspace database (`smb.db`, `winrm.db`, `mssql.db`) | Hosts, credentials, logged-in and admin rights, shares. |
| secretsdump | Hashes, Kerberos keys, cleartext passwords, LSA secrets and cached logons, each tied to its account and host. |
| hashcat potfiles and outfiles | Cracked passwords, joined to the account whose hash they crack. |
| GetUserSPNs and GetNPUsers | Kerberoast and AS-REP hashes, and group memberships. |
| Responder session log and `Responder.db` | Captured hashes and cleartext passwords, with the client host. |
| BloodHound (JSON or zip) | Users, groups, computers, memberships, passwords stated in descriptions, and roastable accounts as findings. |
| certipy `find` | ADCS weaknesses (ESC1, ESC8 and others) as findings on the CA's host. |
| Zip archives | Each file inside is imported on its own. |
| Anything else | Read by the agent, as described above. |

How you save a tool's output changes what Trove can read. [loot/references/capture.md](../loot/references/capture.md) gives the save options to use for each tool and the ones to avoid.

## Walkthrough: castelblack

This follows one host, castelblack, through a GOAD lab: a scan, a question, NetExec output, the same question again, and your own notes. The files are real GOAD lab output in this repository under `tests/corpus/goad/`. Outputs below are from the CLI; the agent's own wording around them varies.

From the repository root, set up a working directory:

```sh
mkdir -p ~/trove-walkthrough/scans ~/trove-walkthrough/enum ~/trove-walkthrough/notes
cp tests/corpus/goad/scans/goad-full.xml ~/trove-walkthrough/scans/
cp tests/corpus/goad/nxc/nxc-cred-check.txt ~/trove-walkthrough/enum/
cd ~/trove-walkthrough
opencode
```

(or `claude` instead of `opencode`).

### 1. Create the engagement

```
/loot-init demo
```

### 2. Import a scan

```
/loot-import scans/goad-full.xml
```

```
goad-full.xml  155772 bytes  parsed by nmap: 5 host, 125 service (130 new, 0 updated)
This import: 130 new record(s), 0 updated
demo now holds: 5 host, 125 service
```

### 3. Ask early

```
/loot-chat what do I have on castelblack?
```

The answer lists `host:192.168.56.22` (castelblack.north.sevenkingdoms.local) and its open services: IIS on 80, SMB on 445, SQL Server on 1433, RDP on 3389, WinRM on 5985 and 5986, and the RPC ports. It also says there are no credentials, shares, findings or notes for castelblack yet. That is "nothing yet", not an error.

### 4. Import NetExec output

```
/loot-import enum/nxc-cred-check.txt
```

```
nxc-cred-check.txt  1783 bytes  parsed by netexec: 5 host, 5 service, 10 finding, 1 credential (11 new, 10 updated)
  note: 1 login(s) succeeded as Guest rather than as the account named on them (essos.local\rickon.stark). A guest fallback proves nothing about that account, so no credential was made from it. The lines are in raw/ verbatim.
  note: 2 login(s) failed and produced no credential. A password that did not work is not that account's password, and recording it would overwrite one that is.
This import: 11 new record(s), 10 updated
demo now holds: 1 credential, 10 finding, 5 host, 125 service
```

`10 updated` means the hosts and services NetExec saw were already held from the scan; they gained NetExec's facts instead of being duplicated. The two notes explain logins that did not become credentials.

### 5. Ask again

```
/loot-chat what do I have on castelblack?
```

Same question, and now the answer also has:

- a credential that works there, `rickon.stark` with password `Winter2022`, confirmed on castelblack and winterfell;
- the finding "SMB signing not required";
- both hostnames, `castelblack.north.sevenkingdoms.local` from the scan and `CASTELBLACK` from NetExec, on one host record.

The credential has no `admin_hosts`, so nothing in the data says it is admin on castelblack, and the answer should not claim it is.

### 6. Check where it came from

```
/loot-find --type credential
```

```
north.sevenkingdoms.local\rickon.stark   (id credential:north.sevenkingdoms.local\rickon.stark+b72c5ada)
  principal   rickon.stark   [tool, nxc-cred-check.txt]
  realm       north.sevenkingdoms.local   [tool, nxc-cred-check.txt]
  secret      Winter2022   [tool, nxc-cred-check.txt]
  state       confirmed   [tool, nxc-cred-check.txt, quote "[+] north.sevenkingdoms.local\rickon.stark:Winter2022"]
  hosts       host:192.168.56.22 (castelblack.north.sevenkingdoms.local)   [tool, nxc-cred-check.txt, quote "192.168.56.22   445    CASTELBLACK      [+] north.sevenkingdoms.local\rickon.stark:Winter2022"]
              host:192.168.56.11 (winterfell.north.sevenkingdoms.local)   [tool, nxc-cred-check.txt, quote "192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\rickon.stark:Winter2022"]
```

Each host the login worked on carries the exact NetExec line that proves it.

### 7. Add your own notes

Write down what you found by hand:

```sh
cat > notes/castelblack.md <<'EOF'
# castelblack

Poked around castelblack (192.168.56.22) this afternoon.

- The IIS site on port 80 has an upload page at /upload that accepts .asp files.
  A web shell looks possible from there.
- Over SMB, the `all` share is readable and writable.

Come back to the upload page tomorrow.
EOF
```

Import it the same way:

```
/loot-import notes/castelblack.md
```

No parser reads your writing, so the agent does. It proposes records such as a finding for the upload page and a share record for `all`, each quoting the sentence it came from, and reports what it kept and dropped. These records have origin `ai`.

### 8. Ask about findings and shares

```
/loot-chat what findings and shares do I have on castelblack?
```

The answer puts them side by side: "SMB signing not required" from NetExec with status `confirmed` (origin `tool`), and the upload page finding and the writable `all` share from your note (origin `ai`). The note's finding is `open`, because only your note says so. It is yours to prove, and you set its status when you do (see [Notes and finding status](#notes-and-finding-status)).

When you're done, `rm -r ~/trove-walkthrough` removes the directory and its engagement.

## Searching

`/loot-find` takes plain words, which must all appear in a record, or filters:

| Filter | Example |
|---|---|
| `--type <type>` (repeatable) | `--type credential` |
| `--where field=value` (repeatable, all must match) | `--where port=445` |
| `--origin tool\|ai\|you` | `--origin ai` |

`--where` operators:

| Operator | Means | Example |
|---|---|---|
| `field=a,b` | equals any of | `port=139,445` |
| `field!=value` | not equal | `state!=open` |
| `field>n`, `field<n` | greater, less | `port<1024` |
| `field~text` | contains | `product~IIS` |
| `field?` | has a value | `admin_hosts?` |
| `field!` | has no value | `secret!` |

`host` means `host_id` and takes an IP or a hostname, so `--where host=castelblack` returns the host and everything linked to it.

Fields by type:

| Type | Fields |
|---|---|
| host | ip, hostnames, os, state |
| service | host_id, port, protocol, name, product, version, banner, state |
| credential | principal, realm, secret, secret_hash, hash_type, state, source, host_id, hosts, admin_hosts, keys |
| principal | principal, realm, sid |
| group | name, realm, dn, sid |
| share | host_id, name, permissions, remark |
| finding | title, description, host_id, service_id, status, suggested_status |
| note | text, tags, host_id |

A protocol's common name (smb, rdp, winrm, mssql, ldap, kerberos, http, ssh, ftp, dns) also finds the services that speak it, so `/loot-find smb` works.

## Notes and finding status

`/loot-note` saves a note with origin `you`. The agent then reads it like any other file and may extract records from it.

```
/loot-note "check the SQL Server on castelblack with rickon.stark" --host 192.168.56.22 --tag todo
```

Find tagged notes later with `/loot-find --type note --where tags=todo`.

A finding's status is one of `open`, `confirmed`, `failed`, `remediated` or `false_positive`. A tool's finding is `confirmed` when the tool saw it; a finding the agent read from a note starts `open`. Only you change a status, by asking, for example: "set finding:… to confirmed". The change is recorded with origin `you`.

## Troubleshooting

**"no engagement here".** Start OpenCode or Claude Code in the directory that holds `<name>.loot/` or below it, or run `/loot-init` first.

**A file is refused.** Encrypted zip members, nested zips and files a parser fails on are stored but not read; the import report names each one and says why.

**A file is pending AI extraction.** `/loot-import` extracts pending files in the same turn unless you passed `--no-ai`. Ask "extract the pending files" to run it later.

**Values are waiting.** Some records need another file first: a SAM dump needs a scan that names its host, and a certipy weakness needs the CA's host. The input waits and is read again after every later import, so import order doesn't change the result.

**A credential is missing.** Guest-fallback logins and failed logins never become credentials; the import report says how many there were. A masked (`********`) secret makes no credential either.

**A tool fails in the lab.** [loot/references/capture.md](../loot/references/capture.md) lists known lab failures and their fixes, for example Kerberos tools failing with `Connection error` on port 88.
