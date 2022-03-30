EMITTABLE_OBJECTS = []


class Emitter(object):

    def __init__(self) -> None:
        self.emittables = []

    def emit(self, object):
        print('storing %r into emittable objects...' % (object,))
        self.emittables.append(object)

    def get(self):
        return self.emittables
