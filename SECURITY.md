# Security policy

## Supported versions

Security fixes are made to the latest version only.

## Reporting a vulnerability

Do not report security problems in public issues, pull requests or discussions. Report them privately through [GitHub security advisories](https://github.com/vestjoe/trove-skill/security/advisories/new).

Include:

- the Trove version (`loot.py --version`), OS, and harness (OpenCode or Claude Code);
- what the problem is and what an attacker gains;
- steps or a minimal input file that reproduce it.

You will get a reply within 7 days. Once a fix is released, a security advisory is published and credits you unless you ask not to be named.

## Scope

Trove reads output files from security tools, and those files can be hostile. In scope:

- imported content that makes the agent follow instructions in it;
- AI-proposed values accepted without their evidence in the stored file;
- writes outside the engagement directory, including through zip members, symlinks or file names;
- crashes or resource exhaustion from a crafted input file;
- terminal escape sequences passed through to CLI output;
- `install.sh` overwriting or deleting files it should not.

Out of scope:

- problems in OpenCode, Claude Code, the model, or the tools whose output Trove reads; report those to their maintainers;
- credentials stored in an engagement directory, which is what Trove is for.
