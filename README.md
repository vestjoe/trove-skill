<p align="center">
  <picture>
    <!-- The colour mark's outline is near-black, so it disappears on a dark
         page. GitHub's dark theme gets the cream monochrome mark instead. -->
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/trove-mark-mono-light.svg">
    <img src="docs/brand/trove-mark.svg" alt="Trove" width="160">
  </picture>
</p>

# Trove

An agent skill for CTF and security-training environments, for OpenCode and Claude Code. You give it tool output and notes; it keeps them in one engagement directory, turns them into records that cite the exact bytes they came from, and answers questions over those records.

- Parsers read nmap (XML, normal, grepable), masscan (XML, grepable, list, JSON, screen), naabu (JSON, XML, grepable), nuclei (JSONL, JSON export, text), NetExec (its output and its workspace database), secretsdump, hashcat/potfile, Responder (its session log and Responder.db), kerberoast and AS-REP hashes, user lists, BloodHound (users, groups, computers, memberships), certipy `find` (ADCS weaknesses) and zips of any of these.
- Anything else (notes, scratch logs) is read by the agent, which proposes records with a quote for each value. A value whose quote is not in the file is dropped.
- Every field says who stated it: `tool` (a parser), `ai` (the agent, quote checked) or `you` (a note you wrote).

The skill is named `loot`, and its commands are `/loot-*`. Standard-library Python only. Scope is CTF and training labs, on Linux and macOS; Windows is not supported yet. The [documentation](https://vestjoe.github.io/trove-skill/) covers usage, the tools Trove reads and a walkthrough; the design is in [docs/SPEC.md](docs/SPEC.md).

## Example

After importing the sample data in `tests/fixtures/`, `/loot-find rickon.stark --type credential` runs the search below, and the agent summarises it. Every value carries its origin, its source file and, where it matters, the exact line it came from:

```
north.acme.local\rickon.stark   (id credential:north.acme.local\rickon.stark+b72c5ada)
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

## Documentation

The full documentation is at <https://vestjoe.github.io/trove-skill/>:

- [Verify your install](https://vestjoe.github.io/trove-skill/install/#verify-your-install) on the sample data, and [uninstall](https://vestjoe.github.io/trove-skill/install/#uninstall).
- [Walkthrough](https://vestjoe.github.io/trove-skill/tutorial/): one host in a GOAD lab, from a scan to your own notes.
- [Commands](https://vestjoe.github.io/trove-skill/commands/) and [the tools Trove reads](https://vestjoe.github.io/trove-skill/tools/), with how to save each tool's output.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) to report bugs or send changes, and [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

MIT; see [LICENSE](LICENSE). The parsers were written clean-room from each tool's own output format; faraday-plugins (GPL-3.0) was consulted only as a behaviour reference, and none of its code is in Trove.
