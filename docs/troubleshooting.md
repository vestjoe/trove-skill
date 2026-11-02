# Troubleshooting

**"no engagement here".** Start OpenCode or Claude Code in the directory that holds `<name>.loot/` or below it, or run `/loot-init` first.

**A file is refused.** Encrypted zip members, nested zips and files a parser fails on are stored but not read; the import report names each one and says why.

**A file is pending AI extraction.** `/loot-import` extracts pending files in the same turn unless you passed `--no-ai`. Ask "extract the pending files" to run it later.

**Values are waiting.** Some records need another file first: a SAM dump needs a scan that names its host, and a certipy weakness needs the CA's host. The input waits and is read again after every later import, so import order doesn't change the result.

**A credential is missing.** Guest-fallback logins and failed logins never become credentials; the import report says how many there were. A masked (`********`) secret makes no credential either.

**A tool fails in the lab.** [capture.md](https://github.com/vestjoe/trove-skill/blob/main/loot/references/capture.md) lists known lab failures and their fixes, for example Kerberos tools failing with `Connection error` on port 88.
