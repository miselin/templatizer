"""Tests for basic templating functionality."""
import unittest

from utils import Simple

# pylint: disable=C0116,R0201


class TestSimpleTemplates(unittest.TestCase):
    """Unit tests for non-imperative templating."""

    def test_simple_property(self):
        obj = Simple()
        self.assertEqual(obj.propval("prop"), 12345)


if __name__ == "__main__":
    unittest.main()
