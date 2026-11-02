# Trove

An agent skill for CTF and security-training environments, for OpenCode and Claude Code. You give it tool output and notes; it keeps them in one engagement directory, turns them into records that cite the exact bytes they came from, and answers questions over those records.

- Parsers read the output of nmap, masscan, naabu, nuclei, NetExec, secretsdump, hashcat, Responder, kerberoast and AS-REP tools, BloodHound and certipy, and zips of any of these. [Tools Trove reads](tools.md) lists the formats.
- The agent reads anything else (notes, scratch logs) and proposes records with a quote for each value. Trove drops a value whose quote is not in the file.
- Every field says who stated it: `tool` (a parser), `ai` (the agent, quote checked) or `you` (a note you wrote).

The skill is named `loot`, and its commands are `/loot-*`. It uses only the Python standard library. Trove is for CTF and training labs on Linux and macOS, and does not support Windows yet.

## Example

Import the sample data in `tests/fixtures/`, then run `/loot-find rickon.stark --type credential`. The agent runs the search below and summarises it. Every value carries its origin, its source file and, where it matters, the exact line it came from:

```
north.acme.local\rickon.stark   (id credential:north.acme.local\rickon.stark+b72c5ada)
  principal   rickon.stark   [tool, fixtures/netexec/nxc-spray.txt]
  realm       north.acme.local   [tool, fixtures/netexec/nxc-spray.txt]
  secret      Winter2022   [tool, fixtures/netexec/nxc-spray.txt]
  state       confirmed   [tool, fixtures/netexec/nxc-spray.txt, quote "[+] north.acme.local\rickon.stark:Winter2022"]
  hosts       host:10.10.10.6 (dc01.lab.local)   [tool, fixtures/netexec/nxc-cred-check.txt, quote "10.10.10.6      445    WINTERFELL       [+] north.acme.local\rickon.stark:Winter2022"]
              host:10.10.10.8 (WS01)   [tool, fixtures/netexec/nxc-cred-check.txt, quote "10.10.10.8      445    CASTELBLACK      [+] north.acme.local\rickon.stark:Winter2022"]
```

## Where to go next

- [Install](install.md) Trove and check the install on the sample data.
- Follow the [walkthrough](tutorial.md): one host in a GOAD lab, from a scan to your own notes.
- Look up the [commands](commands.md) and how to [save each tool's output](tools.md).
- Read [how Trove works](how-it-works.md): engagements, records and where each value comes from.

Trove is MIT licensed. The source, [contributing guide](https://github.com/vestjoe/trove-skill/blob/main/CONTRIBUTING.md) and [security policy](https://github.com/vestjoe/trove-skill/blob/main/SECURITY.md) are on [GitHub](https://github.com/vestjoe/trove-skill).
