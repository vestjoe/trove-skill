# How Trove works

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
