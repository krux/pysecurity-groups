### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Utility classes / functions for pysecurity-groups"""

from pysecurity_groups.exceptions import ParseError


REF_CHAR = '@'


def as_ref(thing):
    """
    Converts THING to a variable reference by prepending the variable
    reference character.

    Raises a ParseError if it is unable to create a variable reference.
    """
    if not responds_to(thing, 'startswith'):
        thing = str(thing)
    thing = thing.lower()
    if thing.startswith(REF_CHAR):
        return thing
    return REF_CHAR + thing


def responds_to(thing, method):
    """
    Returns True if THING has an attribute METHOD and that attribute is
    callable.
    """
    return callable(getattr(thing, method, None))


def uniq(lst):
    """
    Return a list of the unique elements of LST, preserving order.
    """
    seen = {}
    return [seen.setdefault(x, x) for x in lst if x not in seen]


def wrap(value):
    """
    If VALUE is not a sequence, wrap it in a list.

    Sequence types have an __iter__ method, but strings don't. This is exactly
    what I want. I *could* use isinstance, but I prefer checking an objects
    capabilities over checking its type.
    """
    if not responds_to(value, '__iter__'):
        value = [value]
    return value
