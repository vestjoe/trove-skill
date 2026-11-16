# How Trove works

One engagement is one directory: `/loot-init htb-forest` creates `htb-forest.loot/` in the current directory. Every command uses the `<name>.loot/` in the directory where you started OpenCode or Claude Code. If you started inside `<name>.loot/` itself, the command uses that one. A command started in any other subdirectory doesn't find it. To pick a different one, name it in your request ("in the forest engagement…") or start the tool from that engagement's directory.

Trove stores every file you import byte for byte under `raw/`, including files nothing could read. Importing the same file twice changes nothing, unless you name a parser with `--tool` the second time. Then Trove reads the stored file with that parser, so a user list you imported without `--tool users` is read once you add it. A file left for the agent that a parser now recognises is also read again.

Trove builds records from those files. A record is a host, service, credential, principal, group, share, finding, note or relationship (such as a group membership). Records from different files merge: a host from an nmap scan and the same host from NetExec output are one record that lists both files as sources.

![An nmap XML line and a NetExec line both describe 192.168.56.22. Trove stores both files under raw/ and makes one host record, castelblack, whose hostnames come from both files.](assets/diagrams/merge-light.svg#only-light)
![An nmap XML line and a NetExec line both describe 192.168.56.22. Trove stores both files under raw/ and makes one host record, castelblack, whose hostnames come from both files.](assets/diagrams/merge-dark.svg#only-dark)

Some files need a fact from another file before Trove can finish their records. A SAM dump needs a scan that names its host, a certipy weakness needs the CA's host, and a crack needs the dump or hash file that holds its hash. The GOAD dump `secretsdump-castelblack.txt` names its host only as `CASTELBLACK`, in its `$MACHINE.ACC` section. When you import it before any scan, the import report says it can't tie those accounts to a host yet:

```
note: 7 local account(s) belong to CASTELBLACK, which no host Trove holds is called. They are tied to it when a scan names it.
```

The file waits, and Trove reads it again after every later import. When you then import `goad-full.xml`, the report lists `secretsdump-castelblack.txt` as `parsed again`. Its `goadmin` credential now has the host `host:192.168.56.22`, quoting `CASTELBLACK`. With the scan imported first, the dump ties `goadmin` to the same host at once, so import order doesn't change the result.

![The castelblack dump and the scan, imported in either order. With the scan first, the dump ties goadmin to castelblack at once. With the dump first, the dump waits until Trove reads it again after the scan, and goadmin ends up with the same host.](assets/diagrams/import-order-light.svg#only-light)
![The castelblack dump and the scan, imported in either order. With the scan first, the dump ties goadmin to castelblack at once. With the dump first, the dump waits until Trove reads it again after the scan, and goadmin ends up with the same host.](assets/diagrams/import-order-dark.svg#only-dark)

Every value says where it came from: its origin, the file it came from and the exact text Trove read it from. A search shows the quote when it says more than the value itself:

```
state       confirmed   [tool, nxc-cred-check.txt, quote "[+] north.sevenkingdoms.local\rickon.stark:Winter2022"]
```

![A NetExec login line for rickon.stark. The credential's realm, principal and secret each quote their own part of the line, and its state, confirmed, quotes the whole login result.](assets/diagrams/quotes-light.svg#only-light)
![A NetExec login line for rickon.stark. The credential's realm, principal and secret each quote their own part of the line, and its state, confirmed, quotes the whole login result.](assets/diagrams/quotes-dark.svg#only-dark)

| Origin | Meaning |
|---|---|
| `tool` | A parser read it from a tool's output. |
| `ai` | The agent read it from a file no parser handles, and its quote was found in that file. |
| `you` | You wrote it: a note, or a finding status you set. |

When two origins give the same field different values, Trove keeps `you` over `tool` and `tool` over `ai`, so a later import never changes a finding status you set.

The agent reads what parsers can't: notes, scratch logs and output from tools Trove has no parser for. It proposes records, and each proposed value must quote the file word for word. Trove drops a value if its quote isn't in the file. For names, addresses, ports, hashes and passwords, it also drops the value if the value isn't in its own quote. Trove also drops a host name that is a domain it holds, such as `north.sevenkingdoms.local` given as a DC's name. The import report lists what Trove kept and what it dropped.

![A parser reads the nmap line for port 80 on castelblack and makes a service record with origin tool. The agent reads the walkthrough's note and proposes records. Trove keeps a finding and a share with origin ai and drops a description whose quote isn't in the note.](assets/diagrams/parser-agent-light.svg#only-light)
![A parser reads the nmap line for port 80 on castelblack and makes a service record with origin tool. The agent reads the walkthrough's note and proposes records. Trove keeps a finding and a share with origin ai and drops a description whose quote isn't in the note.](assets/diagrams/parser-agent-dark.svg#only-dark)

Each value may quote its own line. A password can quote the `user:password` pair while its domain quotes the heading above the list. When a value is dropped, the agent may send that part of the file once more with a better quote. It never saves a dropped value as a note: a note holds only your own words.

Trove builds the id of a finding the agent proposed from the passage its title quotes and from its host, not from the title. When the agent proposes that finding again with the same passage and a new title, Trove updates the title on the finding it already has.

A file you import can contain text written to steer an AI. Trove and the agent treat everything imported as data and don't follow instructions in it.
