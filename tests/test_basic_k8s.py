"""Tests for basic functionality in templatizer.k8s"""
import unittest

import yaml
from utils import Simple

import templatizer
import templatizer.k8s

# pylint: disable=C0116,R0201


class SimpleK8STemplate(templatizer.k8s.K8STemplatable):
    """A simple Kubernetes template without complex logic."""

    props = ["name", "version"]
    required_props = ["name"]

    def name(self):
        return "test"

    def version(self):
        return "v1"


class InvalidK8STemplate(templatizer.k8s.K8STemplatable):
    """A simple Kubernetes template that is missing a required prop."""

    props = ["name"]
    required_props = ["name"]


class K8STemplateWithYAML(templatizer.k8s.K8STemplatable):
    """A simple Kubernetes template that is missing a required prop."""

    props = ["blob"]

    def blob(self):
        return Simple()


class K8STemplateWithLists(templatizer.k8s.K8STemplatable):
    """A simple Kubernetes template that is missing a required prop."""

    props = ["blobs"]

    def blobs(self):
        return [Simple(), Simple(), Simple(), 56789]


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

    def test_missing_required_props(self):
        obj = InvalidK8STemplate()
        self.assertRaises(ValueError, obj.generate)

    def test_internal_generating(self):
        obj = K8STemplateWithYAML()
        gen = yaml.load(obj.generate(), Loader=yaml.Loader)

        self.assertDictEqual(
            gen,
            {
                "blob": 12345,
            },
        )

    def test_iterable_templatable(self):
        obj = K8STemplateWithLists()
        gen = yaml.load(obj.generate(), Loader=yaml.Loader)

        self.assertDictEqual(
            gen,
            {
                "blobs": [12345, 12345, 12345, 56789],
            },
        )


if __name__ == "__main__":
    unittest.main()
