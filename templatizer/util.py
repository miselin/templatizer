"""Provides YAML utilities that handle specific representation concerns."""
from typing import Any

import yaml


class YamlDumperWithDropAliases(yaml.Dumper):
    """YamlDumperWithDropAliases implements yaml.Dumper but overrides ignore_aliases."""

    def ignore_aliases(self, data):
        return True


def string_as_block(dumper: yaml.Dumper, data: str) -> Any:
    """string_as_block uses YAML's block style for strings with newlines."""
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, string_as_block)


def yamlDump(data: Any) -> str:
    """yamlDump dumps the given data as YAML, with block strings and more."""
    return yaml.dump(data, Dumper=YamlDumperWithDropAliases)
