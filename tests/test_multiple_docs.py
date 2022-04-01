"""Tests for combining multiple documents."""
import unittest

from utils import Simple

import templatizer

# pylint: disable=C0116,R0201


class TestMultipleDocumentGeneration(unittest.TestCase):
    """Unit tests for non-imperative templating."""

    def test_simple_property(self):
        contents = templatizer.run([Simple(), Simple()])
        self.assertEqual(contents, "12345\n---\n12345")


if __name__ == "__main__":
    unittest.main()
