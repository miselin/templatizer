"""Utility classes shared between multiple tests."""
import templatizer


class Simple(templatizer.Templatable):
    """A simple, non-dynamic property in a template."""

    prop = 12345

    def generate(self):
        return str(self.propval("prop"))
