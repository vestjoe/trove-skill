import os

from lootlib import engagement
from lootlib.errors import LootError
from tests.helpers import EngagementCase


class Resolution(EngagementCase):
    def test_init_makes_the_directory_and_refuses_to_make_it_twice(self):
        for sub in ("raw", "records", "notes"):
            self.assertTrue((self.eng.root / sub).is_dir())
        with self.assertRaises(LootError):
            engagement.create("acme", self.tmp)

    def test_a_name_with_a_path_in_it_is_refused(self):
        with self.assertRaises(LootError):
            engagement.create("../evil", self.tmp)

    def test_it_is_found_beside_you_inside_it_and_below_it(self):
        self.assertEqual(engagement.resolve(cwd=self.tmp).root, self.eng.root)
        self.assertEqual(engagement.resolve(cwd=self.eng.root).root, self.eng.root)
        self.assertEqual(engagement.resolve(cwd=self.eng.raw).root, self.eng.root)

    def test_it_is_found_by_name_path_or_environment(self):
        self.assertEqual(engagement.resolve("acme", cwd=self.tmp).root, self.eng.root)
        self.assertEqual(engagement.resolve(str(self.eng.root), cwd=self.tmp.parent).root, self.eng.root)
        os.environ[engagement.ENV] = str(self.eng.root)
        try:
            self.assertEqual(engagement.resolve(cwd=self.tmp.parent).root, self.eng.root)
        finally:
            del os.environ[engagement.ENV]

    def test_two_beside_you_is_a_refusal_naming_both(self):
        engagement.create("other", self.tmp)
        with self.assertRaisesRegex(LootError, "acme.loot, other.loot"):
            engagement.resolve(cwd=self.tmp)

    def test_none_is_a_refusal_that_says_how_to_make_one(self):
        with self.assertRaisesRegex(LootError, "loot init"):
            engagement.resolve(cwd=self.eng.root.parent.parent)
