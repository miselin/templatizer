"""Tests for basic templating functionality."""
import unittest

import templatizer

# pylint: disable=C0116,R0201


class Simple(templatizer.Templatable):
    """A simple, non-dynamic property in a template."""

    prop = 12345

    def generate(self):
        return str(self.propval("prop"))


class TestSimpleTemplates(unittest.TestCase):
    """Unit tests for non-imperative templating."""

    def test_simple_property(self):
        obj = Simple()
        self.assertEqual(obj.propval("prop"), 12345)


if __name__ == "__main__":
    unittest.main()
