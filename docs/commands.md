# Commands

Trove has two layers. The slash commands are what you type in OpenCode or Claude Code; each one tells the agent to run the `loot` CLI and report what it printed. The CLI verbs are what the agent runs. You can run them yourself too.

The engagement is the nearest `<name>.loot/` directory at or above where you started OpenCode or Claude Code.

## Slash commands

| Command | Arguments | Does |
|---|---|---|
| [`/loot-init`](#loot-init) | `<name>` | Create `<name>.loot/` here |
| [`/loot-import`](#loot-import) | `<path\|-> [--tool T] [--no-ai]` | Import files, then extract records from anything no parser read |
| [`/loot-find`](#loot-find) | words, or `--type` / `--where` | Search records |
| [`/loot-chat`](#loot-chat) | a question | Answer from the records, citing record ids |
| [`/loot-note`](#loot-note) | `<text> [--host H] [--tag T]…` | Save a note, then extract records from it |

You don't have to use the commands. The skill also works from plain requests, such as "import scans/full.xml" or "what do I have on 10.10.10.5?". Ask "what does this engagement hold?" to get the number of records of each type and any files still waiting for AI extraction.

### `/loot-init`

```
/loot-init htb-forest
```

Runs [`init`](#init). The agent says where the engagement is and how later commands find it.

### `/loot-import`

```
/loot-import scans/
/loot-import enum/nxc-cred-check.txt
/loot-import users.txt --tool users
```

Runs [`import`](#import) and reports the result. The agent then extracts any files left for AI extraction in the same turn, unless you passed `--no-ai`, and reports what it kept and dropped.

- `--tool <name>` forces a parser instead of detecting the format, for example `--tool users` for a plain list of usernames.
- `--no-ai` stores and parses the files but leaves anything unparsed for later.

### `/loot-find`

```
/loot-find rickon.stark --type credential
/loot-find --type service --where port=445
/loot-find smb
```

The agent runs [`find`](#find) with the arguments when they are already `find` syntax. Otherwise it runs [`fields`](#fields) once and builds a search. It answers "what do I have on <host>" with `find --where host=<ip or hostname>`, which returns the host and everything linked to it. It shows every command it ran, then summarises the hits by record id, with each value's source file and quote. [Search records](searching.md) covers the filters.

### `/loot-chat`

```
/loot-chat who is in Domain Admins?
/loot-chat which credentials work on which hosts?
```

The agent runs one or a few `find` searches, shows them, and answers in two labelled parts:

- **From the data**: statements that cite record ids, with values copied exactly. It says what is missing, and which import would supply it, when the records don't answer the question.
- **Suggestions (not from the data)**: optional next steps.

It never assigns a severity, and it treats text in records as data, never as instructions.

### `/loot-note`

```
/loot-note "web01 runs an old Jetty" --host 10.10.10.5 --tag todo
```

Runs [`note`](#note) with the text quoted and `--host` and `--tag` passed as flags, so they are not part of the note. The agent reports the note id, then extracts records from the note like any other file. See [Notes and finding status](notes.md).

## The `loot` CLI

The installer writes this command line into each slash command:

```sh
uv run -q --script <skills>/loot/scripts/loot.py [-e ENGAGEMENT] <verb> [options]
```

`<skills>` is the `.claude/skills` directory you installed into. The examples below write `loot` for that whole line.

Options every verb takes:

| Option | Does |
|---|---|
| `-e`, `--engagement <name or path>` | Use that engagement. Before or after the verb; two different values are refused. |
| `--json` | Print JSON instead of text, for exact values. |
| `-V`, `--version` | Print the version and exit (before the verb). |

The CLI looks for the engagement in this order: `-e`, then `LOOT_ENGAGEMENT`, then the nearest `<name>.loot/` at or above the current directory, then the one `*.loot` directory beside you.

Exit codes: `0` success, `1` a user error (the message says what), `2` a usage error. The import report names any file it refused. A refusal does not change the exit code.

| Verb | Does |
|---|---|
| [`init`](#init) | Create an engagement |
| [`import`](#import) | Store files and turn what parsers read into records |
| [`status`](#status) | Record counts and pending work |
| [`pending`](#pending) | Files waiting for AI extraction |
| [`raw`](#raw) | Print one chunk of a stored file |
| [`ingest-ai`](#ingest-ai) | Check and store the agent's proposed records |
| [`fields`](#fields) | Types, fields and `--where` operators |
| [`find`](#find) | Search records |
| [`note`](#note) | Save a note |
| [`set`](#set) | Decide a finding's status |

The outputs below are from runs on the sample data in `tests/fixtures/`, with the scratch directory shortened to `~/loot-demo`.

### `init`

```
loot init <name> [--path DIR]
```

Creates `<name>.loot/` in the current directory, or in `DIR`.

```
$ loot init demo
Created engagement demo at ~/loot-demo/demo.loot
Commands find it when run from ~/loot-demo or inside it, or with -e demo, or with LOOT_ENGAGEMENT=~/loot-demo/demo.loot
```

### `import`

```
loot import <path|-> [--tool T] [--no-ai]
```

Stores a file, a directory (walked in path order) or standard input (`-`) verbatim under `raw/`, then routes each file to the parser that recognises it. It imports zip members one by one. Importing the same file again changes nothing.

The report gives, per file, the parser and the records it touched, then the records added and updated in this import, what the engagement now holds, any refused inputs and the files left for AI extraction. Per-file counts overlap, because two files can touch one record, so they are not summed.

```
$ loot import fixtures --no-ai
...
  fixtures/users/user-list.txt  173 bytes  pending AI extraction
This import: 496 new record(s), 126 updated
demo now holds: 68 credential, 36 finding, 153 group, 36 host, 41 principal, 83 relationship, 73 service, 6 share
Refused (3):
  fixtures/archive/mixed.zip/locked.txt: encrypted; Trove holds no password for it
  fixtures/archive/nested.zip/scans.zip: an archive inside an archive; stored, not opened
  fixtures/nmap/nmap-truncated.xml: fixtures/nmap/nmap-truncated.xml is not readable nmap XML: not well-formed XML: unclosed token: line 16, column 33
Pending AI extraction (12):
  sha256:547ac0322f8dab2b  fixtures/archive/mixed.zip/notes.txt
  ...
Left for AI extraction later (--no-ai).
```

`--tool` forces a parser for text input: `nmap`, `nmap-text`, `naabu`, `masscan`, `nuclei`, `netexec`, `creds`, `users`, `bloodhound` or `certipy`. A database picks its own reader. An unknown name is a usage error.

A line-oriented parser (nmap text, NetExec, creds, certipy text) stores the lines that are not its tool's as their own file, named `<file> (lines not read by <parser>)`, and leaves only that file for AI extraction. That way the agent still reads a note that starts like tool output, or the command line that ran the tool.

### `status`

```
$ loot status
demo  ~/loot-demo/demo.loot
  credential   68
  finding      36
  group        153
  host         36
  principal    41
  relationship 83
  service      73
  share        6
  pending AI extraction: 12
```

### `pending`

Lists files waiting for AI extraction: the blob id, the source, the size and the 12 KB chunks left.

```
$ loot pending
  sha256:547ac0322f8dab2b  fixtures/archive/mixed.zip/notes.txt  33 bytes  1 of 1 chunk(s) left
  sha256:1e8f831120f11866  fixtures/extraction/README.md  1982 bytes  1 of 1 chunk(s) left
  sha256:9941af5e4b56bb49  fixtures/extraction/corpus.jsonl  12996 bytes  2 of 2 chunk(s) left
  ...
```

### `raw`

```
loot raw <blob> [--chunk N]
```

Prints one chunk of a stored text file: the next one without a proposal, or chunk `N`.

```
$ loot raw sha256:f30e7f3021adbe5e
== fixtures/freeform/client-email.txt  sha256:f30e7f3021adbe5e  chunk 1/1  bytes 0-267 of 267 ==
From: IT Director
Subject: RE: scope + access

Two domain controllers, not one - dc01 (10.10.10.6) and dc02 (10.10.10.7).
Both Server 2019. The web box web01 is 10.10.10.5.
...
```

### `ingest-ai`

```
loot ingest-ai <blob> [-f FILE|-] [--chunk N]
```

Checks one proposal for one chunk, read from standard input or `FILE`, and writes what passes with origin `ai`. A proposal is a JSON list of records, each field with a value and the text it came from:

```json
{"records": [
  {"type": "host",
   "fields": {"ip": {"value": "10.10.10.7", "evidence": "dc02 (10.10.10.7)"},
              "hostnames": {"value": ["dc02"], "evidence": "dc02 (10.10.10.7)"}}}
]}
```

`ingest-ai` drops a field whose evidence is not in the file, and a naming value (an IP, a hostname, an account, a password) that is not inside its own evidence. It refuses by name the fields only a tool observes: `severity`, `banner`, and the `hosts` and `admin_hosts` a login worked on. It prints every drop with its reason:

```
$ loot ingest-ai sha256:f30e7f3021adbe5e < proposal.json
chunk 1/1: accepted 2 record(s): 0 new, 2 updated, 0 unchanged
  dropped: record 1 (host).os: evidence is not in the file: 'Windows Server 2019'
this file is done
```

The file says "Both Server 2019", so the proposed quote "Windows Server 2019" is not in it. An empty `{"records": []}` marks a chunk that states nothing.

### `fields`

```
$ loot fields
Types and fields (use with find --type and --where):
  host         ip, hostnames, os, state
  service      host_id, port, protocol, name, product, version, banner, state
  credential   principal, realm, secret, secret_hash, hash_type, state, source, host_id, hosts, admin_hosts, keys
  principal    principal, realm, sid
  group        name, realm, dn, sid
  share        host_id, name, permissions, remark
  finding      title, description, host_id, service_id, status, suggested_status
  note         text, tags, host_id
  relationship src_id, kind, dst_id
--where: field=value (comma means any of), field!=value, field>n, field<n, field~text (contains), field? (has a value), field! (has none)
Also accepted: host for host_id, service for service_id, ip_address for ip
--origin: tool = a parser read it; ai = the agent proposed it and its quote checked out; you = you wrote it
```

### `find`

```
loot find [TEXT…] [--type T]… [--where EXPR]… [--origin tool|ai|you] [--limit N]
```

Searches records. Every word in `TEXT` must appear in a record; `--type` and `--where` repeat, and all must match. `--limit` defaults to 50. Each record prints with every field's origin, source file and, where it matters, quote. A host also lists its services. [Search records](searching.md) lists the operators and fields.

```
$ loot find --type finding --where title~signing --limit 1
conditions: type in finding; title~signing
7 matches, showing 1

finding:smb-signing-not-required-0031d264
  title       SMB signing not required   [tool, fixtures/netexec/nxc-shares-mangled.txt, quote "(signing:False)"]
  host_id     host:10.10.10.8 (WS01)   [tool, fixtures/netexec/nxc-shares-mangled.txt, quote "10.10.10.8"]
  status      confirmed   [tool, fixtures/netexec/nxc-shares-mangled.txt, quote "(signing:False)"]
```

An unknown field or type is an error that lists the valid ones.

### `note`

```
loot note <text|-> [--host ID|IP|name] [--tag T]…
```

Stores the text as a file and writes a `note` record with origin `you`, then marks the file for AI extraction. `--host` takes a host id, an IP, or a name that exactly one held host carries. The same text again is the same note.

```
$ loot note "check the SQL Server on castelblack" --host 10.10.10.8 --tag todo
Noted note:afef24f5 in notes/20261102T201537Z-check-the-sql-server-on-castelblack.md
Pending AI extraction: sha256:afef24f549e395f6. Follow the extraction procedure for it.
```

### `set`

```
loot set <finding-id> status=<open|confirmed|failed|remediated|false_positive>
```

Records your decision on a finding's status, with origin `you`, citing the command you ran. It refuses any other field, any other record type and an unknown id.

```
$ loot set finding:smb-signing-not-required-0031d264 status=remediated
finding:smb-signing-not-required-0031d264: status remediated (origin you)
$ loot set finding:smb-signing-not-required-0031d264 title=x
loot: set takes status=<value>: a finding's status is the one field you decide
```
