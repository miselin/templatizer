
import yaml

from collections.abc import Iterable

from templatizer import Templatable, NoValue


def fixValue(val):
    if isinstance(val, list):
        return [fixValue(v) for v in val]

    # Other templatable objects should be emitted correctly
    if isinstance(val, Templatable):
        val = yaml.load(val.generate(), Loader=yaml.Loader)

    return val


class K8STemplatable(Templatable):
    description = NoValue
    apiVersion = NoValue
    kind = NoValue
    required_props = []

    def __init__(self, **kwargs) -> None:
        super().__init__()

        for k, v in kwargs.items():
            setattr(self, k, v)

    def generate(self):
        document = {}

        props = self.propval('props')
        required_props = self.propval('required_props')
        for p in props:
            val = self.propval(p)
            # K8S-specific feature: returning None also ignores the value
            if val is not NoValue and val:
                val = fixValue(val)
                document[p] = val
            elif p in required_props:
                raise ValueError('no value for required property "%s"' % (p,))

        return yaml.dump(document)
