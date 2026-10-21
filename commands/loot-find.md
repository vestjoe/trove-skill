---
description: Search the current Trove engagement
---
Use the `loot` skill. Search for: $ARGUMENTS

If that is already `loot find` syntax (words, --type, --where), run `{{LOOT}} find $ARGUMENTS`. Otherwise run `{{LOOT}} fields` once, then build a `{{LOOT}} find` command for it.
A protocol's common name (smb, rdp, winrm, mssql, ldap, kerberos, http, ssh, ftp, dns) also finds the services that speak it, by scan name and port. If a plain-word search finds nothing, try once more with `--type`/`--where`.
For "what do I have on <host>", run `{{LOOT}} find --where host=<ip or hostname>`: one call returns the host and everything linked to it.
Show every command you ran, then summarise the hits by record id. For each value you mention, give its source file and quote as the output prints them.
