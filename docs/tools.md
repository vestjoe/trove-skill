# Tools Trove reads

## What becomes records

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
| Anything else | Read by the agent; see [How Trove works](how-it-works.md). |

## Saving tool output

How you save a tool's output changes what Trove can read. Save each tool's output this way, chosen from the tool's own save options. [capture.md](https://github.com/vestjoe/trove-skill/blob/main/loot/references/capture.md) explains each choice and the options to avoid; the skill gives the same advice.

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
