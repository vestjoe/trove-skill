# Contributing to Trove

[docs/SPEC.md](docs/SPEC.md) defines what Trove does: scope, layout, data format, CLI and commands. A change to any of those updates the spec in the same pull request. Trove is standard-library Python only, for Linux and macOS. For a new feature, open an issue first that describes the problem it solves.

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Reporting bugs

Open an issue with:

- the Trove version (`loot.py --version`), OS, and harness (OpenCode or Claude Code);
- the command you ran and what it printed;
- what you expected instead;
- for a parser bug, a minimal input file that reproduces it.

Attach only synthetic or lab data, never output from a real engagement.

## Development

You need [uv](https://docs.astral.sh/uv/) and git.

```sh
git clone https://github.com/vestjoe/trove-skill.git trove
cd trove
uv run --python 3.11 python -m unittest discover -s tests -t .
```

To try a change in OpenCode or Claude Code, install it into a scratch project with `./install.sh --opencode --project DIR` or `./install.sh --claude --project DIR`, then follow "Verify your install" in the [README](README.md).

## Pull requests

1. Branch from `main` and keep one change per pull request.
2. Follow the code rules in [AGENTS.md](AGENTS.md).
3. Add or update tests. A new parser or format adds a fixture under `tests/fixtures/` and its source in `tests/SOURCES.md`. A new capture of the GOAD lab adds to `tests/corpus/goad/` and its command to `tests/corpus/SOURCES.md`.
4. Update `docs/SPEC.md` and the README where behaviour changes.
5. Run the tests. CI runs them on Linux and must pass before merge.

Test data must be synthetic or from a lab: no real hosts, credentials, client names or personal data.

## License

Contributions are licensed under the [MIT License](LICENSE).
