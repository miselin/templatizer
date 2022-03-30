#!/usr/bin/env python3
"""
generate.py loads a Kubernetes OpenAPI spec and generates base classes.
"""

import json
import sys
import keyword

from typing import Tuple


DEFN_PREFIX = '#/definitions/'

IGNORED_PREFIXES = (
    'io.k8s.apiextensions-apiserver.',
)


def fixKeyword(name: str) -> str:
    if name in keyword.kwlist:
        return 'k8s_%s' % (name,)
    else:
        return name.replace('-', '_')


def definitionToClass(defn: str) -> str:
    return defn.replace('.', '__').replace('-', '_')


def getVersionAndKind(v: dict) -> Tuple[str]:
    if v.get('group'):
        return ('{group}/{version}'.format(**v), v['kind'])
    else:
        return ('{version}'.format(**v), v['kind'])


def definitionToType(defn):
    if not defn.startswith(DEFN_PREFIX):
        raise ValueError('trying to ref a type that does not start with #/definitions/')

    defn = defn[len(DEFN_PREFIX):]

    for prefix in IGNORED_PREFIXES:
        if defn.startswith(prefix):
            return None

    defn = definitionToClass(defn)
    return defn


def createReferencedTypeAnnotation(propspec):
    ref = propspec.get('$ref')
    if ref is None:
        raise ValueError('neither type or $ref are set')

    return definitionToType(ref)


def createTypeAnnotation(propspec):
    """Returns a (annotation, [dependent classes]) tuple"""
    proptype = propspec.get('type')
    if proptype is None:
        result = createReferencedTypeAnnotation(propspec)
        if result is None:
            return (None, [])
        return (result, [result])

    if proptype == 'array':
        itemspec = propspec.get('items')
        if itemspec is None:
            raise ValueError('no items field for array type')

        # This will handle $ref and other types automatically
        classname, classes = createTypeAnnotation(itemspec)
        return ('List[%s]' % (classname), classes)
    elif proptype == 'string':
        return ('str', [])
    elif proptype == 'integer':
        return ('int', [])
    elif proptype == 'boolean':
        return ('bool', [])
    elif proptype == 'number':
        return ('float', [])
    elif proptype == 'object':
        # give up on types
        return (None, [])


def main():
    if len(sys.argv) != 3:
        print('Usage: generate.py swagger.json [outfile]', file=sys.stderr)
        exit(1)

    with open(sys.argv[1], encoding='utf-8') as f:
        # Don't keep anything other than the definitions in memory
        # (the "paths" map is much larger than "definitions")
        spec = json.load(f)['definitions']

    # TODO(miselin): handle OneOf, AnyOf, AllOf etc
    classes = {}
    simplified_mappings = {}
    for k, spec in spec.items():
        ok = True
        for prefix in IGNORED_PREFIXES:
            if k.startswith(prefix):
                ok = False
                break

        if not ok:
            continue

        orig_k = k
        k = definitionToClass(k)

        apiBlock = ''
        if 'x-kubernetes-group-version-kind' in spec:
            apiVersion, kind = getVersionAndKind(spec.get('x-kubernetes-group-version-kind')[0])
            apiBlock = '''
    apiVersion: str = "{apiVersion}"
    kind: str = "{kind}"
'''.format(apiVersion=apiVersion, kind=kind)

            if kind in simplified_mappings:
                kind = '%s_%s' % (apiVersion.replace('/', '_').replace('.', '__'), kind)
            simplified_mappings[kind] = k
        else:
            kind = orig_k.split('.')[-1]
            simplified_mappings[kind] = k

        props = []
        propkeys = []
        deps = []
        prop_params = []
        for prop, propspec in spec.get('properties', {}).items():
            if prop in ('anyOf', 'default', 'allOf', '$ref', '$schema', 'not'):
                continue

            if prop in ('apiVersion', 'kind') and apiBlock != '':
                propkeys.append(prop)
                continue

            annotation = createTypeAnnotation(propspec)
            if annotation is None:
                continue  # not available
            proptype, propclasses = annotation
            if k in propclasses:
                # can't currently emit classes that reference themselves
                continue

            if proptype:
                params = (fixKeyword(prop), proptype)
                props.append('    %s: %s' % params)
                prop_params.append((params[0], '%s: %s = None' % params))
            else:
                fixed = fixKeyword(prop)
                props.append('    %s: Any' % (fixed,))
                prop_params.append((fixed, '%s: Any = None' % (fixed,)))

            propkeys.append(fixKeyword(prop))
            deps.extend(propclasses)

        required = spec.get('required', [])

        if prop_params:
            kwargs = ', ' + ', '.join(x[1] for x in prop_params)
        else:
            kwargs = ''

        constructor = '''
    def __init__(self{kwargs}, **kwargs):
        super().__init__()
'''.format(**{'kwargs': kwargs})

        for param, _ in prop_params:
            constructor += '        if {prop} is not None:\n            self.{prop} = {prop}\n'.format(prop=param)

        classes[k] = (deps, '''
class {classname}(K8STemplatable):
    """{description}"""
    {apiBlock}
    props: List[str] = [{propkeys}]
    required_props: List[str] = {required}

{props}

{constructor}
'''.format(**{
    'classname': k,
    'description': spec.get('description'),
    'apiBlock': apiBlock,
    'props': '\n'.join(props),
    'propkeys': ', '.join(['"%s"' % (prop,) for prop in propkeys]),
    'required': '%r' % (required,),
    'constructor': constructor,
}))

    emitted_classes = set()
    with open(sys.argv[2], 'w', encoding='utf-8') as f:
        f.write('''"""AUTO-GENERATED FILE: DO NOT EDIT"""
# pylint: skip-file
# flake8: noqa

from typing import Any, List

from . import K8STemplatable

''')

        iters = 0

        while classes and iters < 10000:
            iters += 1
            for k, (deps, pycode) in list(classes.items()):
                if set(deps).issubset(emitted_classes):
                    print('emitting %s' % (k,))
                    f.write(pycode)
                    del classes[k]
                    emitted_classes.add(k)
                #else:
                #    # print('class %s missing deps %s' % ())

        if iters >= 10000:
            print('ran out of iterations, remaining classes:')
            for k in classes.keys():
                print(k)

                # which deps aren't here?
                x = set(classes[k][0]).difference(emitted_classes)
                print(x)

        for kind, klass in simplified_mappings.items():
            f.write('%s = %s\n' % (kind, klass))




if __name__ == '__main__':
    main()
