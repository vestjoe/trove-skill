# Commands

Each command runs the `loot` skill. The engagement is the nearest `<name>.loot/` directory at or above where you started OpenCode or Claude Code.

| Command | Does | Example |
|---|---|---|
| `/loot-init <name>` | Create `<name>.loot/` in the current directory. | `/loot-init htb-forest` |
| `/loot-import <path>` | Import a file, a directory or `-` for stdin, then have the agent extract records from anything no parser read. | `/loot-import scans/` |
| `/loot-find <search>` | Search records. Accepts plain words or `--type` and `--where` (see [Search records](searching.md)). | `/loot-find --type service --where port=445` |
| `/loot-chat <question>` | Ask a question. The answer lists what the records say, each fact cited by record id, then any suggestions, labelled as not from the data. | `/loot-chat "who is in Domain Admins?"` |
| `/loot-note <text>` | Save a note. Add `--host <ip or name>` to tie it to a host, and `--tag <tag>` (repeatable) to tag it. | `/loot-note "web01 runs an old Jetty" --host 10.10.10.5 --tag todo` |

## `/loot-import` options

- `--tool <name>` forces a parser instead of detecting the format, for example `--tool users` for a plain list of usernames.
- `--no-ai` stores and parses the files but leaves anything unparsed for later.

## Plain requests

You don't have to use the commands. The skill also works from plain requests, such as "import scans/full.xml" or "what do I have on 10.10.10.5?". Ask "what does this engagement hold?" to get the number of records of each type and any files still waiting for AI extraction.
