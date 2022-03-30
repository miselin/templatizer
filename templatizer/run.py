
from typing import List

from .emitter import Emitter
from .templatable import Templatable


def run(objects: List[Templatable], separator: str = '---'):
    emitter = Emitter()
    for o in objects:
        emitter.emit(o)

    documents = []
    for emittable in emitter.get():
        documents.append(emittable.generate())

    return separator.join(documents)
