"""Utility classes shared between multiple tests."""
import string
import templatizer


class Simple(templatizer.Templatable):
    """A simple, non-dynamic property in a template."""

    prop = 12345

    def generate(self):
        return str(self.propval("prop"))


class MultilineString(templatizer.Templatable):
    """A simple, non-dynamic property in a template (multi-line string)."""

    prop = '\n'.join(string.ascii_lowercase)

    def generate(self):
        return templatizer.yamlDump(self.propval("prop"))
