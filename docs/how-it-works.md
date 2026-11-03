# How Trove works

One engagement is one directory. `/loot-init htb-forest` creates `htb-forest.loot/` in the current directory. Every command uses the `<name>.loot/` in the directory where you started OpenCode or Claude Code, or the one you started inside. A command started in a subdirectory of that directory doesn't find it. To pick a different one, name it in your request ("in the forest engagement…") or start the tool from that engagement's directory.

Trove keeps every file you import as it is. It stores the bytes verbatim under `raw/`, including files nothing could read. Importing the same file twice changes nothing.

Trove builds records from those files. A record is a host, service, credential, principal, group, share, finding, note or relationship (such as a group membership). Records from different files merge: a host from an nmap scan and the same host from NetExec output are one record that cites both.

Every value says where it came from. Each field shows its origin, the file it came from and, where it matters, the exact text quoted from that file:

```
state       confirmed   [tool, nxc-cred-check.txt, quote "[+] north.sevenkingdoms.local\rickon.stark:Winter2022"]
```

| Origin | Meaning |
|---|---|
| `tool` | A parser read it from a tool's output. |
| `ai` | The agent read it from a file no parser handles, and its quote was found in that file. |
| `you` | You wrote it: a note, or a finding status you set. |

The agent reads what parsers can't: notes, scratch logs and output from tools Trove has no parser for. It proposes records, and each proposed value must quote the file word for word. Trove drops a value if its quote isn't in the file. For names, addresses, ports, hashes and passwords, it also drops the value if the value isn't in its own quote. The import report lists what Trove kept and what it dropped.

Imported text is data. A file can contain text meant to steer an AI, and Trove treats everything it imports as data, never as instructions.
