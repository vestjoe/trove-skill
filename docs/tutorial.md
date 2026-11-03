# Walkthrough: castelblack

This follows one host, castelblack, through a GOAD lab: a scan, a question, NetExec output, the same question again, and your own notes. The files are real GOAD lab output in this repository under [`tests/corpus/goad/`](https://github.com/vestjoe/trove-skill/tree/main/tests/corpus/goad). [Install](install.md) Trove first. Outputs below are excerpts from the CLI; the agent's own wording around them varies.

From the repository root, set up a working directory:

```sh
mkdir -p ~/trove-walkthrough/scans ~/trove-walkthrough/enum ~/trove-walkthrough/notes
cp tests/corpus/goad/scans/goad-full.xml ~/trove-walkthrough/scans/
cp tests/corpus/goad/nxc/nxc-cred-check.txt ~/trove-walkthrough/enum/
cd ~/trove-walkthrough
opencode
```

(or `claude` instead of `opencode`).

## 1. Create the engagement

```
/loot-init demo
```

## 2. Import a scan

```
/loot-import scans/goad-full.xml
```

```
goad-full.xml  155772 bytes  parsed by nmap: 5 host, 125 service (130 new, 0 updated)
This import: 130 new record(s), 0 updated
demo now holds: 5 host, 125 service
```

## 3. Ask early

```
/loot-chat what do I have on castelblack?
```

The answer lists `host:192.168.56.22` (castelblack.north.sevenkingdoms.local) and its open services: IIS on 80, SMB on 139 and 445, SQL Server on 1433 and 49792, RDP on 3389, WinRM on 5985 and 5986, HTTPAPI on 47001, and the RPC ports. It also says there are no credentials, shares, findings or notes for castelblack yet. That is "nothing yet", not an error.

## 4. Import NetExec output

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

`10 updated` means Trove already held the hosts and services NetExec saw, from the scan. They gained NetExec's facts, and Trove made no duplicates. The two notes explain logins that did not become credentials.

## 5. Ask again

```
/loot-chat what do I have on castelblack?
```

Same question, and now the answer also has:

- a credential that works there, `rickon.stark` with password `Winter2022`, confirmed on castelblack and winterfell;
- the finding "SMB signing not required";
- both hostnames, `castelblack.north.sevenkingdoms.local` from the scan and `CASTELBLACK` from NetExec, on one host record.

The credential has no `admin_hosts`, so nothing in the data says it is admin on castelblack, and the answer should not claim it is.

## 6. Check where it came from

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

## 7. Add your own notes

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

## 8. Ask about findings and shares

```
/loot-chat what findings and shares do I have on castelblack?
```

The answer puts them side by side: "SMB signing not required" from NetExec with status `confirmed` (origin `tool`), and the upload page finding and the writable `all` share from your note (origin `ai`). The note's finding is `open`, because only your note says so. It is yours to prove, and you set its status when you do (see [Notes and finding status](notes.md)).

When you're done, `rm -r ~/trove-walkthrough` removes the directory and its engagement.

