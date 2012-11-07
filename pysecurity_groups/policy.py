### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Policy functions for pysecurity-groups."""
import re

from IPy import IP


_REF_CHAR      = '@'
_ASSIGN_CHAR   = '='
_LIST_CHAR     = ','
_COMMENT_CHAR  = '#'
_VAR           = r'([-\w]+)'
_VAR_RE        = re.compile(r'(?i)'+_VAR)
_ASSIGN_RE     = re.compile(r'(?i)^\s*'+_VAR+r'\s*=\s*\b(.+)?.*$')
_VAR_REF_RE    = re.compile(r'(?i)'+_REF_CHAR+_VAR)


def is_assignment(line):
    """
    Predicate to determine whether LINE is a variable assignment.

    LINE is a variable assignment if it contains _ASSIGN_CHAR.
    """
    return _ASSIGN_RE.search(line)


def canonical(thing):
    """
    Return THING in canonical form.
    """
    result = thing
    # Lowercase
    if callable(getattr(result, 'lower', None)):
        result = result.lower()
    # Strip leading/trailing whitespace
    if callable(getattr(result, 'strip', None)):
        result = result.strip()
    return result


def as_ref(thing):
    """
    Create a variable reference from THING.

    Raises TypeError if a variable reference cannot be created from THING.
    """
    try:
        if _VAR_REF_RE.match(thing):
            return thing
        elif _VAR_RE.match(thing):
            return _REF_CHAR + thing
        else:
            raise TypeError
    except TypeError:
        raise TypeError("could not create a variable reference from "
                        "'%s'" % repr(thing))


def parse_assignment(line, environment):
    """
    Parse LINE, (a variable assignment,) and assign the variable name to its
    value. Uses lazy assignment in order to avoid ordering issues.
    """
    if not is_assignment(line):
        raise ValueError("'%s' is not a variable assignment")

    name, _, value = [canonical(thing) for thing in line.partition(_ASSIGN_CHAR)]

    def resolve(env, stack=None):
        """
        Resolve a variable to it's value. Raises ValueError if a cyclical
        assignment is detected.
        """
        if stack is None:
            # Throw the variable we're resolving on the new stack to save a
            # step during cycle detection.
            stack = [as_ref(name)]
        # If the value isn't iterable, we can't check if it contains
        # _REF_CHAR. This only happens if we've got a value that is not a
        # string anymore, which means it is already fully resolved, so we can
        # just return it.
        if not callable(getattr(value, '__iter__', None)):
            return value
        resolved = value        # need to capture 'value' as a local to modify
        # As long as unresolved variable references remain in the string, we
        # keep looping, attempting to resolve the references. This allows us
        # to have variables that expand into values containing other
        # variables.
        while _REF_CHAR in resolved:
            references = _VAR_REF_RE.findall(resolved)
            for reference in references:
                if reference in stack:
                    # There's already a pending resolution for this reference,
                    # which indicates a cycle.
                    cycle = ' -> '.join(stack + [reference])
                    raise ValueError('cyclical variable reference: %s' % cycle)
                stack.append(reference) # Track the pending resolution.
                try:
                    resolved = re.sub(reference, env[reference](env,stack), resolved)
                except KeyError:
                    raise ValueError('undefined variable %s '
                                     'while resolving %s' % (reference, as_ref(name)))
                # remove the current resolution from the stack now that it is
                # no longer pending.
                stack.pop()
        return resolved

    return dict(environment.items() + {as_ref(name): resolve}.items())


def strip_comments(iterable):
    """
    """
    for line in iterable:
        if _COMMENT_CHAR in line:
            yield line[:line.index(_COMMENT_CHAR)]
        else:
            yield line


# TODO: THIS DOESN"T WORK.
def continue_lines(iterable):
    for line in iterable:
        next_line = ''
        if line.endswith(_LIST_CHAR):
            next_line = iterable.next()
        while line.endswith(_LIST_CHAR) and _LEAD_SPACE_RE.search(next_line):
            line += next_line.strip()
            next_line = iterable.next()
        yield line
        yield next_line


def parse(policy_file):
    environment = {}
    with open(args.policy, 'r') as policy_file:
        stripped = (line.rstrip() for line in strip_comments(policy_file))
        continued = continue_lines(stripped)
        assignments = (line for line in continued if is_assignment(line))
        for assignment in assignments:
            environment.update(parse_assignment(assignment, environment).items())
        for key, value in environment.items():
            environment[key] = value(environment)
    return environment
