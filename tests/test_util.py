### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Tests for the pysecurity-groups utility classes / functions."""

from nose.tools import assert_equal # pylint: disable=E0611

import pysecurity_groups.util as util
from pysecurity_groups.exceptions import ParseError
from pysecurity_groups.util import REF_CHAR


class TestAsRef(object):
    """
    Tests for the as_ref utility function.
    """
    def test_as_ref_return_type(self):
        """
        The return value of as_ref is a string.
        """
        objects = [object(), ParseError('Error'), {'test': 'foo'}, 'string']
        expected = [REF_CHAR + str(obj) for obj in objects]
        assert(all([isinstance(util.as_ref(obj), str) for obj in objects]))

    def test_as_ref_capitalization(self):
        """
        Strings returned by as_ref are lower-case.
        """
        strings = ['lower-case', 'UPPER-CASE', 'MixedCase']
        expected = [REF_CHAR + abc.lower() for abc in strings]
        result = [util.as_ref(abc) for abc in strings]
        assert_equal(expected, result)

    def test_as_ref_prefix(self):
        """
        Strings returned by as_ref begin with the reference character.
        """
        strings = ['test1', 'test2', '@test3']
        expected = ['@test1', '@test2', '@test3']
        result = [util.as_ref(abc) for abc in strings]
        assert_equal(expected, result)


class TestUniq(object):
    """
    Tests for the uniq utility function.
    """
    def test_uniq_items(self):
        """
        Lists returned by uniq contain only unique items.
        """
        lists = [[1, 1, 1, 2],
                 [1, 2, 3, None],
                 [5, 4, 4, 4, 4, 4],
                 [1, 1, 1, 1],
                 ['foo', 'bar', 2, 'bar', 'quux', False]]
        # We have to sort the results so that we don't get false failures due
        # to ordering. This doesn't affect the test, which is just checking
        # that the items are unique.
        expected = [sorted(list(set(lst))) for lst in lists]
        result = [sorted(util.uniq(lst)) for lst in lists]
        assert_equal(expected, result)

    def test_uniq_ordering(self):
        """
        Calls to uniq preserve ordering of input lists.
        """
        lists = [[3, 1, 4, 1, 5, 9, 2, 6, 5],
                 [None, 'alpha', None, False, 123, -54, 123, 'foo']]
        expected = [[3, 1, 4, 5, 9, 2, 6],
                    [None, 'alpha', False, 123, -54, 'foo']]
        result = [util.uniq(lst) for lst in lists]
        assert_equal(expected, result)


class TestWrap(object):
    """
    Tests for the wrap utility function.
    """
    def test_wrap_list(self):
        """
        Calling wrap on a list returns the list, unchanged.
        """
        lists = [[1, 1, 1, 2],
                 [1, 2, 3, None],
                 [5, 4, 4, 4, 4, 4],
                 [1, 1, 1, 1],
                 ['foo', 'bar', 2, 'bar', 'quux', False]]
        result = [util.wrap(lst) for lst in lists]
        assert_equal(lists, result)

    def test_wrap_generator(self):
        """
        Calling wrap on a generator returns the generator, unchanged.
        """
        def a_gen():
            for i in range(10):
                yield i
        gens = [a_gen(), a_gen(), a_gen()]
        result = [util.wrap(gen) for gen in gens]
        assert_equal(gens, result)

    def test_wrap_string(self):
        """
        Calling wrap on a string returns a list of that string.
        """
        strings = ['lower-case', 'UPPER-CASE', 'MixedCase']
        expected = [[abc] for abc in strings]
        result = [util.wrap(abc) for abc in strings]
        assert_equal(expected, result)

    def test_wrap_object(self):
        """
        Calling wrap on a non-iterable object returns a list of that object.
        """
        objects = [object() for i in range(10)]
        expected = [[obj] for obj in objects]
        result = [util.wrap(obj) for obj in objects]
        assert_equal(expected, result)
