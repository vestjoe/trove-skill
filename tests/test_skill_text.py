import contextlib
import io
import os
import re
import shlex

from lootlib import cli
from tests import CORPUS, ROOT
from tests.helpers import EngagementCase

READ_ONLY = {"find", "fields", "status", "pending"}
_SPAN = re.compile(r"`(?:loot|\{\{LOOT\}\}) ([^`]+)`")


def command_lines():
    """Every `loot …` command written in a file the model reads, with where it was written."""
    files = [ROOT / "loot/SKILL.md", *sorted((ROOT / "loot/references").glob("*.md")),
             *sorted((ROOT / "commands").glob("*.md"))]
    for path in files:
        for found in _SPAN.finditer(path.read_text()):
            yield path.relative_to(ROOT), found.group(1)


class SkillText(EngagementCase):
    """The commands the skill text tells the model to run exist and run on a real engagement."""

    def setUp(self):
        super().setUp()
        self.run_cli("import", str(CORPUS), "--no-ai")

    def run_cli(self, *argv):
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                code = cli.main(list(argv))
        finally:
            os.chdir(cwd)
        return code, err.getvalue()

    def test_every_command_names_a_real_verb(self):
        verbs = set(cli.build_parser()._subparsers._group_actions[0].choices)
        for where, line in command_lines():
            with self.subTest(where=str(where), line=line):
                self.assertIn(line.split()[0], verbs)

    def test_every_complete_read_only_command_runs(self):
        ran = 0
        for where, line in command_lines():
            if line.split()[0] not in READ_ONLY or re.search(r"[<…[]|\$ARGUMENTS|\.\.\.", line):
                continue
            with self.subTest(where=str(where), line=line):
                code, err = self.run_cli(*shlex.split(line))
                self.assertEqual(code, 0, err)
                ran += 1
        self.assertGreaterEqual(ran, 8)

    def test_chat_says_to_copy_secrets_exactly(self):
        text = " ".join((ROOT / "loot/references/chat.md").read_text().split())
        self.assertIn("character for character", text)
        self.assertIn("never correct one", text)

    def test_find_says_to_show_source_and_quote(self):
        text = " ".join((ROOT / "commands/loot-find.md").read_text().split())
        self.assertIn("source file and quote", text)
