### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Tests for the policy module of pysecurity-groups."""

import nose
from nose.tools import *

import pysecurity_groups.policy as policy


def test_is_assignment():
    """
    Make sure the is_assignment predicate properly detects variable
    assignments.
    """
    valid = ['foo=bar', 'Bar = baz', 'baz\t=\tQuux\t', 'foo2 = multi word value']
    invalid = ['', '# foo = bar', 'GROUP foobar', 'two word = invalid']
    assert_true(all([policy.is_assignment(line) for line in valid]))
    assert_false(any([policy.is_assignment(line) for line in invalid]))


def test_canonical():
    """
    Make sure the canonical function correctly returns values in canonical
    form.
    """
    assert_equal(policy.canonical('foo'), 'foo')
    assert_equal(policy.canonical('Foo'), 'foo')
    assert_equal(policy.canonical('   foo Bar BAZ\t'), 'foo bar baz')
    assert_equal(policy.canonical({}), {})


def test_as_ref():
    """
    Make sure as_ref correctly translates strings into variable references.
    """
    thing = '@foo'
    assert_equal(policy.as_ref(thing), thing)
    thing = 'foo'
    assert_equal(policy.as_ref(thing), policy._REF_CHAR + thing)
    thing = '   leadingspaces'
    assert_raises(TypeError, policy.as_ref, thing)
    thing = {}
    assert_raises(TypeError, policy.as_ref, thing)


if __name__ == '__main__':
    nose.main()
