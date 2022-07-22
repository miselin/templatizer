"""Tests for imperative functionality in templates."""
import unittest

from templatizer.yamlblob import YamlBlob

# pylint: disable=C0116,R0201


class YamlBlobWithNewlines(YamlBlob):
    """Defines a YamlBlob class that should generate YAML blocks."""

    def data(self):
        return {
            "a": "b",
            "blob": "foo\nbar\nbaz",
        }


class YamlBlobWithSharedObjects(YamlBlob):
    """Defines a YamlBlob class that has keys pointing at the same object."""

    def data(self):
        shared = {"foo": "bar"}
        return {
            "a": shared,
            "b": shared,
        }


class TestImperativeTemplates(unittest.TestCase):
    """Unit tests for imperative generation."""

    def test_imperative_property(self):
        obj = YamlBlobWithNewlines()
        self.assertEqual(
            obj.generate(),
            """a: b
blob: |-
  foo
  bar
  baz
""",
        )


class TestNoAliases(unittest.TestCase):
    """Unit tests for yaml without aliases."""

    def test_no_aliases_generated(self):
        obj = YamlBlobWithSharedObjects()
        self.assertEqual(
            obj.generate(),
            """a:
  foo: bar
b:
  foo: bar
""",
        )


if __name__ == "__main__":
    unittest.main()
