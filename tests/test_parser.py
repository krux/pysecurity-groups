### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Tests for the pysecurity-groups rules file parser."""

from nose.tools import assert_equal, assert_true # pylint: disable=E0611

from pysecurity_groups import parser as parser


class TestLexer(object):
    """
    Tests for the lexer component of the parser.
    """
    def setUp(self):
        """
        Create a lexer object for use by tests.
        """
        self.lexer = parser.SGLexer()

    def test_comment(self):
        """
        Ensure that the lexer ignores comments.
        """
        input_text = '# This is a comment.'
        self.lexer.input(input_text)
        assert_equal(list(self.lexer), [])

    def test_whitespace(self):
        """
        Ensure that the lexer ignores whitespace. The input_text here includes
        space characters and literal tabs.
        """
        input_text = """

            """
        self.lexer.input(input_text)
        assert_equal(list(self.lexer), [])

    def test_varref(self):
        """
        Ensure that the lexer properly tokenizes variable references.
        """
        input_text = '@this_is_a_variable @SO_IS_THIS '
        input_text += '@Mixed_CASE_too @AND_numbers_1234'
        self.lexer.input(input_text)
        assert_true(all([t.type == 'VARREF' for t in self.lexer]))

    def test_assign(self):
        """
        Ensure that the lexer properly tokenizes assignment statements.
        """
        input_text = 'variable_name = value'
        self.lexer.input(input_text)
        tokens = list(self.lexer)
        assert_equal(len(tokens), 2)
        assert_equal(tokens[0].type, 'ASSIGN')
        assert_equal(tokens[0].value, 'variable_name')
        assert_equal(tokens[1].type, 'ID')
        assert_equal(tokens[1].value, 'value')
