# Install

## Requirements

- [uv](https://docs.astral.sh/uv/) on your `PATH` (it fetches Python 3.11+ if you don't have it):

  ```sh
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

- [OpenCode](https://opencode.ai) or [Claude Code](https://claude.com/claude-code).
- git, to clone this repository.

## Run the installer

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

## Verify your install

This uses the sample data in `tests/fixtures/` (synthetic and lab data). From the repository root, make a scratch directory with a copy of it and start your tool there:

```sh
mkdir -p ~/loot-demo
cp -R tests/fixtures ~/loot-demo/fixtures
cd ~/loot-demo
opencode
```

(or `claude` instead of `opencode`). Then run these five commands in order.

1. `/loot-init demo`

   Correct: it creates `demo.loot/` in `~/loot-demo` and says later commands find it from this directory.

2. `/loot-import fixtures`

   Correct: 77 files read (99 inputs once zip members are counted). 3 are refused and named (an encrypted zip member, a nested zip, a truncated nmap XML). 12 files are pending AI extraction, and the agent extracts them in the same turn, then reports what it kept and dropped. A dropped host link for "dc01" or "dc02" is correct: two hosts in the sample data carry each name. This step takes a few minutes.

3. `/loot-find smb`

   Correct: services on port 445 (and 139 where a scan named it) on the 10.10.10.x, 10.10.20.x and 192.168.56.x hosts, and the SMB findings such as "SMB signing not required", each with the file it came from.

4. `/loot-chat "which credentials work on which hosts?"`

   Correct: under **From the data**, the credentials a login confirmed, each with its hosts and cited by record id: `rickon.stark` (north.acme.local) on 10.10.10.6 and 10.10.10.8, `svc_backup` on 10.10.10.6, `Administrator` (essos.local) on 10.10.10.9, admin there (`admin_hosts`), `Administrator` (lab-01.local) on 10.10.20.10 and 10.10.20.22, admin on 10.10.20.10, `backup.ops` on 10.10.20.21 and 10.10.20.10, admin on both, `jojen.reed` on 192.168.56.24, admin there, and `goadmin` (north.sevenkingdoms.local) on 192.168.56.22, admin there. Other credentials (hashes, AS-REP, kerberoast) are named as not tried anywhere, not given a guessed host. It may also mention what the sample notes claim (for example svc_backup on 10.10.10.7); that is correct only if it says those come from `ai` extraction, not from a login. Any advice is under **Suggestions (not from the data)**.

5. `/loot-note "jon.snow kerberoast hash still uncracked" --host 10.10.10.6 --tag todo`

   Correct: it reports a `note:` id. The note text has no `--host` or `--tag` in it; `/loot-find --type note` shows `host_id host:10.10.10.6` and tag `todo`. The agent may also extract a credential from the note.

When you're done, `rm -r ~/loot-demo` removes the scratch directory and its engagement.

## Uninstall

Remove what the installer added:

| Tool | Scope | Remove |
|---|---|---|
| OpenCode | all projects | `~/.claude/skills/loot` and `~/.config/opencode/commands/loot-*.md` |
| OpenCode | one project | `DIR/.claude/skills/loot` and `DIR/.opencode/commands/loot-*.md` |
| Claude Code | all projects | `~/.claude/skills/loot` and `~/.claude/skills/loot-*` |
| Claude Code | one project | `DIR/.claude/skills/loot` and `DIR/.claude/skills/loot-*` |

For example, for Claude Code on all projects:

```sh
rm -r ~/.claude/skills/loot ~/.claude/skills/loot-*
```

Your `<name>.loot/` engagement directories are never touched by install or uninstall.

