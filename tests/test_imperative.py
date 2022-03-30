import unittest

import templatizer


class Simple(templatizer.Templatable):
    prop = 12345


class Imperative(templatizer.Templatable):
    tick = 0

    def prop(self):
        return 12345 + self.tick


class TestTemplatizer(unittest.TestCase):

    def test_imperative_property(self):
        obj = Imperative()
        self.assertEqual(obj.propval('prop'), 12345)

        obj.tick = 1
        self.assertEqual(obj.propval('prop'), 12346)


if __name__ == '__main__':
    unittest.main()
