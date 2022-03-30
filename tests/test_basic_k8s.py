import unittest
import yaml

import templatizer
import templatizer.k8s


class SimpleK8STemplate(templatizer.k8s.K8STemplatable):
    props = ['name', 'version']

    def name(self):
        return 'test'

    def version(self):
        return 'v1'


class TestTemplatizer(unittest.TestCase):

    def test_simple_generation(self):
        obj = SimpleK8STemplate()
        gen = yaml.load(obj.generate(), Loader=yaml.Loader)

        self.assertDictEqual(gen, {
            'name': 'test',
            'version': 'v1',
        })


if __name__ == '__main__':
    unittest.main()
