import unittest

import templatizer


class Simple(templatizer.Templatable):
    prop = 12345


class Imperative(templatizer.Templatable):

    def prop(self):
        return 12345


class TestTemplatizer(unittest.TestCase):

    def test_simple_property(self):
        obj = Simple()
        self.assertEqual(obj.propval('prop'), 12345)

    def test_imperative_property(self):
        obj = Imperative()
        self.assertEqual(obj.propval('prop'), 12345)


if __name__ == '__main__':
    unittest.main()
