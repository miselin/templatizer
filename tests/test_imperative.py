"""Tests for imperative functionality in templates."""
import unittest

import templatizer

# pylint: disable=C0116,R0201


class Imperative(templatizer.Templatable):
    """An imperative template that can change behavior dynamically."""

    tick = 0

    def prop(self):
        return 12345 + self.tick

    def generate(self):
        return str(self.propval("prop"))


class TestImperativeTemplates(unittest.TestCase):
    """Unit tests for imperative generation."""

    def test_imperative_property(self):
        obj = Imperative()
        self.assertEqual(obj.propval("prop"), 12345)

        obj.tick = 1
        self.assertEqual(obj.propval("prop"), 12346)


if __name__ == "__main__":
    unittest.main()
