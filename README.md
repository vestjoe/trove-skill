<p align="center">
  <picture>
    <!-- The colour mark's outline is near-black, so it disappears on a dark
         page. GitHub's dark theme gets the cream monochrome mark instead. -->
    <source media="(prefers-color-scheme: dark)" srcset="brand/trove-mark-mono-light.svg">
    <img src="brand/trove-mark.svg" alt="Trove" width="160">
  </picture>
</p>

# Trove

An agent skill for CTF and security-training environments, for OpenCode and Claude Code. You give it tool output and notes; it keeps them in one engagement directory, turns them into records that cite the exact bytes they came from, and answers questions over those records.

- Parsers read nmap (XML, normal, grepable), masscan (XML, grepable, list, JSON, screen), naabu (JSON, XML, grepable), nuclei (JSONL, JSON export, text), NetExec (its output and its workspace database), secretsdump, hashcat/potfile, Responder (its session log and Responder.db), kerberoast and AS-REP hashes, user lists, BloodHound (users, groups, computers, memberships), certipy `find` (ADCS weaknesses) and zips of any of these.
- Anything else (notes, scratch logs) is read by the agent, which proposes records with a quote for each value. A value whose quote is not in the file is dropped.
- Every field says who stated it: `tool` (a parser), `ai` (the agent, quote checked) or `you` (a note you wrote).

The skill is named `loot`, and its commands are `/loot-*`. Standard-library Python only. Scope is CTF and training labs, on Linux and macOS; Windows is not supported yet. The [user guide](docs/GUIDE.md) covers usage, the tools Trove reads and a walkthrough; the design is in [docs/SPEC.md](docs/SPEC.md).

## Example

After importing the sample data in `tests/fixtures/`, `/loot-find rickon.stark --type credential` runs the search below, and the agent summarises it. Every value carries its origin, its source file and, where it matters, the exact line it came from:

```
credential:north.acme.local\rickon.stark-b72c5ada
  principal   rickon.stark   [tool, fixtures/netexec/nxc-spray.txt]
  realm       north.acme.local   [tool, fixtures/netexec/nxc-spray.txt]
  secret      Winter2022   [tool, fixtures/netexec/nxc-spray.txt]
  state       confirmed   [tool, fixtures/netexec/nxc-spray.txt, quote "[+] north.acme.local\rickon.stark:Winter2022"]
  hosts       host:10.10.10.6 (dc01.lab.local)   [tool, fixtures/netexec/nxc-cred-check.txt, quote "10.10.10.6      445    WINTERFELL       [+] north.acme.local\rickon.stark:Winter2022"]
              host:10.10.10.8 (WS01)   [tool, fixtures/netexec/nxc-cred-check.txt, quote "10.10.10.8      445    CASTELBLACK      [+] north.acme.local\rickon.stark:Winter2022"]
```

## Requirements

- [uv](https://docs.astral.sh/uv/) on your `PATH` (it fetches Python 3.11+ if you don't have it):

  ```sh
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

- [OpenCode](https://opencode.ai) or [Claude Code](https://claude.com/claude-code).
- git, to clone this repository.

## Install

Clone the repository and run the installer from it:

```sh
git clone https://github.com/vestjoe/trove-skill.git trove
cd trove
```

| Tool | Scope | Command |
|---|---|---|
| OpenCode | all projects | `./install.sh --opencode --global` |
| OpenCode | one project | `./install.sh --opencode --project /path/to/project` |
| Claude Code | all projects | `./install.sh --claude --global` |
| Claude Code | one project | `./install.sh --claude --project /path/to/project` |

The skill goes in a `.claude/skills/loot` directory, which both OpenCode and Claude Code read; the commands go where each tool looks for them. Running the installer again updates an existing install. It refuses to overwrite a `.claude/skills/loot` directory that isn't a Trove install.

Restart OpenCode or Claude Code afterwards so it picks up the new commands.

## Commands

Each command runs the `loot` skill. The engagement is the nearest `<name>.loot/` directory at or above where you started OpenCode or Claude Code.

| Command | Does | Example |
|---|---|---|
| `/loot-init` | Create `<name>.loot/` here | `/loot-init htb-forest` |
| `/loot-import` | Import a file, a directory, or `-` for stdin; then the agent extracts records from files no parser reads | `/loot-import scans/` |
| `/loot-find` | Search records by words, `--type` or `--where` | `/loot-find --type service --where port=445` |
| `/loot-chat` | Ask a question; the answer cites record ids | `/loot-chat "who is in Domain Admins?"` |
| `/loot-note` | Save a note, optionally tied to a host or tagged | `/loot-note "web01 runs an old Jetty" --host 10.10.10.5 --tag todo` |

## Saving tool output

Trove reads each tool's output best when it is saved one way, chosen from the tool's own save options. [loot/references/capture.md](loot/references/capture.md) explains each choice and what to avoid; the skill gives the same advice.

| Tool | Save it like this | Import |
|---|---|---|
| nmap | `nmap -sC -sV -oA scans/<name> <targets>` | `scans/<name>.xml` |
| masscan | `sudo masscan <targets> -p1-65535 --banners --source-ip <unused-ip> -oX scans/<name>.xml` | the `.xml` |
| naabu | `naabu -host <targets> -p - -json -o scans/<name>.json` | the `.json` |
| nuclei | `nuclei -l targets.txt -j -o scans/<name>.jsonl` | the `.jsonl` |
| NetExec | set `log_mode = True` in `~/.nxc/nxc.conf` once, or add `--log nxc/<what>.log` to one run | `~/.nxc/logs/`, or the `.log` |
| NetExec database | make a workspace per engagement first: `nxcdb`, then `workspace create <name>` | `~/.nxc/workspaces/<name>/` |
| secretsdump | `secretsdump.py '<domain>/<user>:<pass>@<ip>' \| tee dumps/secretsdump-<ip>.txt` | the `.txt` |
| GetUserSPNs, GetNPUsers | `GetUserSPNs.py -request -dc-ip <ip> <domain>/<user>:<pass> \| tee roast/spns-<domain>.txt` | the `.txt` |
| hashcat | crack with the potfile on (the default), or `--potfile-path loot.pot` | the potfile, after the dump that holds the hashes |
| Responder | run it as usual | `Responder-Session.log` and `Responder.db` in the `logs/` folder of Responder's install |
| BloodHound | `bloodhound-ce-python -d <domain> -u <user> -p <pass> -ns <dc-ip> -c All --zip` | the `.zip` |
| certipy | `certipy find -u <user>@<domain> -p <pass> -dc-ip <ip> -json -output adcs/<domain>` | `adcs/<domain>_Certipy.json` |

## Verify your install

This uses the sample data in `tests/fixtures/` (synthetic and lab data). From the repository root, make a scratch directory with a copy of it and start your tool there:

```sh
mkdir -p ~/loot-demo
cp -R tests/fixtures ~/loot-demo/fixtures
cd ~/loot-demo
opencode
```

(or `claude` instead of `opencode`). Then run these five commands in order.

1. `/loot-init demo`

   Correct: it creates `demo.loot/` in `~/loot-demo` and says later commands find it from this directory.

2. `/loot-import fixtures`

   Correct: 77 files read (99 inputs once zip members are counted). 3 are refused and named (an encrypted zip member, a nested zip, a truncated nmap XML). 12 files are pending AI extraction, and the agent extracts them in the same turn, then reports what it kept and dropped. A dropped host link for "dc01" or "dc02" is correct: two hosts in the sample data carry each name. This step takes a few minutes.

3. `/loot-find smb`

   Correct: services on port 445 (and 139 where a scan named it) on the 10.10.10.x, 10.10.20.x and 192.168.56.x hosts, and the SMB findings such as "SMB signing not required", each with the file it came from.

4. `/loot-chat "which credentials work on which hosts?"`

   Correct: under **From the data**, the credentials a login confirmed, each with its hosts and cited by record id: `rickon.stark` (north.acme.local) on 10.10.10.6 and 10.10.10.8, `svc_backup` on 10.10.10.6, `Administrator` (essos.local) on 10.10.10.9, admin there (`admin_hosts`), `Administrator` (lab-01.local) on 10.10.20.10 and 10.10.20.22, admin on 10.10.20.10, `backup.ops` on 10.10.20.21 and 10.10.20.10, admin on both, `jojen.reed` on 192.168.56.24, admin there, and `goadmin` (north.sevenkingdoms.local) on 192.168.56.22, admin there. Other credentials (hashes, AS-REP, kerberoast) are named as not tried anywhere, not given a guessed host. It may also mention what the sample notes claim (for example svc_backup on 10.10.10.7); that is correct only if it says those come from `ai` extraction, not from a login. Any advice is under **Suggestions (not from the data)**.

5. `/loot-note "jon.snow kerberoast hash still uncracked" --host 10.10.10.6 --tag todo`

   Correct: it reports a `note:` id. The note text has no `--host` or `--tag` in it; `/loot-find --type note` shows `host_id host:10.10.10.6` and tag `todo`. The agent may also extract a credential from the note.

When you're done, `rm -r ~/loot-demo` removes the scratch directory and its engagement.

## Uninstall

Remove what the installer added:

| Tool | Scope | Remove |
|---|---|---|
| OpenCode | all projects | `~/.claude/skills/loot` and `~/.config/opencode/commands/loot-*.md` |
| OpenCode | one project | `DIR/.claude/skills/loot` and `DIR/.opencode/commands/loot-*.md` |
| Claude Code | all projects | `~/.claude/skills/loot` and `~/.claude/skills/loot-*` |
| Claude Code | one project | `DIR/.claude/skills/loot` and `DIR/.claude/skills/loot-*` |

For example, for Claude Code on all projects:

```sh
rm -r ~/.claude/skills/loot ~/.claude/skills/loot-*
```

Your `<name>.loot/` engagement directories are never touched by install or uninstall.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) to report bugs or send changes, and [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

MIT; see [LICENSE](LICENSE). The parsers were written clean-room from each tool's own output format; faraday-plugins (GPL-3.0) was consulted only as a behaviour reference, and none of its code is in Trove.
