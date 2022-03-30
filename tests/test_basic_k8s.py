"""Tests for basic functionality in templatizer.k8s"""
import unittest

import yaml

import templatizer
import templatizer.k8s

# pylint: disable=C0116,R0201


class SimpleK8STemplate(templatizer.k8s.K8STemplatable):
    """A simple Kubernetes template without complex logic."""

    props = ["name", "version"]

    def name(self):
        return "test"

    def version(self):
        return "v1"


class TestBasicK8STemplating(unittest.TestCase):
    """Unit tests for basic Kubernetes template functionality."""

    def test_simple_generation(self):
        obj = SimpleK8STemplate()
        gen = yaml.load(obj.generate(), Loader=yaml.Loader)

        self.assertDictEqual(
            gen,
            {
                "name": "test",
                "version": "v1",
            },
        )


if __name__ == "__main__":
    unittest.main()
