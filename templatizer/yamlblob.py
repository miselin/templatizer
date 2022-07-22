"""Provides YAML 'blob' template classes for embedding YAML as strings."""
from typing import Any

from .templatable import Templatable
from .util import yamlDump


class YamlBlob(Templatable):
    """YamlBlob embeds data as a YAML string."""

    def data(self) -> Any:
        """data returns the raw data to be YAML-encoded."""
        raise NotImplementedError("data() must be implemented on ConfigurationData")

    def generate(self) -> Any:
        return yamlDump(self.data())
