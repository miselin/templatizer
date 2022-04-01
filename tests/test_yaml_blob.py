"""Tests for imperative functionality in templates."""
import unittest

from templatizer.yamlblob import YamlBlob

# pylint: disable=C0116,R0201


class YamlBlobWithNewlines(YamlBlob):

    def data(self):
        return {
            'a': 'b',
            'blob': 'foo\nbar\nbaz',
        }


class TestImperativeTemplates(unittest.TestCase):
    """Unit tests for imperative generation."""

    def test_imperative_property(self):
        obj = YamlBlobWithNewlines()
        self.assertEqual(obj.generate(), '''a: b
blob: |-
  foo
  bar
  baz
''')


if __name__ == "__main__":
    unittest.main()
