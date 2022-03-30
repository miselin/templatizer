
from types import FunctionType

class _ValueClass(object):
    pass


# Global NoValue can be used to omit a value (because a function that does not return any value returns None)
NoValue = _ValueClass()


class Templatable(object):
    """An object that is able to be converted into a template."""

    def generate(self):
        raise NotImplementedError('generate() must be implemented')

    def propval(self, k):
        try:
            v = getattr(self, k)
        except AttributeError:
            v = NoValue

        if v is NoValue:
            return v
        elif callable(v):
            return v()
        else:
            return v
