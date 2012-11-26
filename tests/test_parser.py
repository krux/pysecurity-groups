### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Tests for the pysecurity-groups rules file parser."""

from IPy import IP
from nose.tools import assert_equal, assert_raises, assert_true # pylint: disable=E0611
from nose.plugins.skip import SkipTest

from pysecurity_groups import parser as parser
from pysecurity_groups.exceptions import ParseError


class TestLexer(object):
    """
    Tests for the lexer component of the parser.
    """
    def setUp(self):
        """
        Create a lexer object for use by tests.
        """
        self.lexer = parser.SGLexer()

    ### It is worth noting that the input_text used in the lexer tests is not
    ### (necessarily) VALID in the pysecurity-groups policy language. In this
    ### class we're only testing the lexer to see that it properly identifies
    ### tokens. Valid syntax will be tested in the parser tests.

    def test_comment(self):
        """
        The lexer ignores comments.
        """
        input_text = '# This is a comment.'
        self.lexer.input(input_text)
        assert_equal(list(self.lexer), [])

    def test_whitespace(self):
        """
        The lexer ignores whitespace.
        """
        # The input_text here includes space characters and literal tabs.
        input_text = """

            """
        self.lexer.input(input_text)
        assert_equal(list(self.lexer), [])

    def test_varref(self):
        """
        The lexer properly tokenizes variable references.
        """
        input_text = '@this_is_a_variable @SO_IS_THIS '
        input_text += '@Mixed_CASE_too @AND_numbers_1234'
        self.lexer.input(input_text)
        assert_true(all([t.type == 'VARREF' for t in self.lexer]))

    def test_assign(self):
        """
        The lexer properly tokenizes assignment statements.
        """
        input_text = 'variable_name = value'
        self.lexer.input(input_text)
        tokens = list(self.lexer)
        assert_equal(len(tokens), 2)
        assert_equal(tokens[0].type, 'ASSIGN')
        assert_equal(tokens[0].value, 'variable_name')
        assert_equal(tokens[1].type, 'ID')
        assert_equal(tokens[1].value, 'value')

    def test_id(self):
        """
        The lexer properly tokenizes reserved words and identifiers.
        """
        input_text = 'FROM TO GROUP tcp udp icmp'
        expected = [('FROM', 'FROM'),
                    ('TO', 'TO'),
                    ('GROUP', 'GROUP'),
                    ('PROTO', 'tcp'),
                    ('PROTO', 'udp'),
                    ('PROTO', 'icmp')]
        self.lexer.input(input_text)
        tokens = [(token.type, token.value) for token in self.lexer]
        assert_equal(tokens, expected)

    def test_cidr(self):
        """
        The lexer properly tokenizes CIDR ranges.
        """
        input_text = '0.0.0.0/0 192.168.0.0 10.0.0.0/8 8.8.8.8 192.168.252.0/24'
        expected = [('CIDR', IP(cidr)) for cidr in input_text.split()]
        self.lexer.input(input_text)
        tokens = [(token.type, token.value) for token in self.lexer]
        assert_equal(tokens, expected)

    def test_range(self):
        """
        The lexer properly tokenizes range specifiers.
        """
        input_text = '* 5555:5560 22 1:4'
        expected = [('*', '*'),
                    ('RANGE', {'end': 5560, 'start': 5555}),
                    ('RANGE', 22),
                    ('RANGE', {'end': 4, 'start': 1}),]
        self.lexer.input(input_text)
        tokens = [(token.type, token.value) for token in self.lexer]
        assert_equal(tokens, expected)


class TestParser(object):
    """
    Tests for the pysecurity-groups policy language parser.
    """
    def setUp(self):
        """
        Create a parser object for use by tests.
        """
        self.parser = parser.SGParser(debug=1)

    def test_assignment(self):
        """
        The parser properly parses variable assignments.
        """
        input_text = '''
        ssh = 22
        http-ports = 80, 443, 8080
        office-ips = 10.0.1.1,
                     10.0.1.2
        home-ips   = 192.168.1.1,
                     192.168.1.2,
        '''
        expected = {'@home-ips': [IP('192.168.1.1'), IP('192.168.1.2')],
                    '@http-ports': [80, 443, 8080],
                    '@office-ips': [IP('10.0.1.1'), IP('10.0.1.2')],
                    '@ssh': 22}
        result = self.parser.parse(input_text)['variables']
        assert_equal(result, expected)

    def test_assignment_recursive(self):
        """
        The parser properly parses recursive variable assignments.
        """
        input_text = '''
        http-ports = 80, 8080
        https = 443
        web-ports = @http-ports, @https
        '''
        expected = {'@http-ports': [80, 8080, 443],
                    '@https': 443,
                    '@web-ports': [80, 8080, 443]}
        result = self.parser.parse(input_text)['variables']
        assert_equal(result, expected)

    def test_duplicate_assignment(self):
        """
        The parser raises an error on duplicate assignment.
        """
        input_text = '''
        some-port = 1234
        some-port = 2345
        '''
        assert_raises(ParseError, self.parser.parse, input_text)

    def test_invalid_variable_name(self):
        """
        The parser raises an error for invalid variable names.
        """
        input_text = '1invalid-name = 1234'
        assert_raises(ParseError, self.parser.parse, input_text)

    def test_malformed_assignment(self):
        """
        The parser raises an error for malformed assignment statements.
        """
        input_text = 'varname = '
        assert_raises(ParseError, self.parser.parse, input_text)

    def test_group_declaration(self):
        """
        The parser properly parses group declarations.
        """
        input_text = '''
        GROUP test-group-1
        GROUP TEST-Group-2
        '''
        expected = set(['test-group-1', 'TEST-Group-2'])
        result = self.parser.parse(input_text)['groups']
        assert_equal(result, expected)

    def test_group_redeclaration(self):
        """
        The parser ignores duplicate group declarations.
        """
        input_text = '''
        GROUP test-group-1
        GROUP TEST-Group-2
        GROUP test-group-1
        '''
        expected = set(['test-group-1', 'TEST-Group-2'])
        result = self.parser.parse(input_text)['groups']
        assert_equal(result, expected)

    def test_rule_source_varref(self):
        """
        The parser properly parses variable references as sources.
        """
        input_text = '''
        anywhere = 0.0.0.0/0
        FROM @anywhere tcp 22 TO test-group
        '''
        expected = [{'destination': ['test-group'],
                     'proto': ['tcp'],
                     'range': [22],
                     'source': [IP('0.0.0.0/0')]}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_rule_source_wildcard(self):
        """
        The parser properly parses the '*' as a wild card source.
        """
        input_text = '''
        FROM * tcp 22 TO test-group
        '''
        expected = [{'destination': ['test-group'],
                     'proto': ['tcp'],
                     'range': [22],
                     'source': [IP('0.0.0.0/0')]}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_rule_source_cidr(self):
        """
        The parser properly parses a CIDR range as a source.
        """
        input_text = '''
        FROM 10.0.0.0/8 tcp 22 TO test-group
        '''
        expected = [{'destination': ['test-group'],
                     'proto': ['tcp'],
                     'range': [22],
                     'source': [IP('10.0.0.0/8')]}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_rule_source_group(self):
        """
        The parser properly parses a group name as a source.
        """
        input_text = '''
        FROM test-group-2 tcp 22 TO test-group-1
        '''
        expected = [{'destination': ['test-group-1'],
                     'proto': ['tcp'],
                     'range': [22],
                     'source': ['test-group-2']}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_rule_protocol(self):
        """
        The parser properly parses protocol specifiers.
        """
        input_text = '''
        FROM test-group tcp 53 TO dns-servers
        FROM test-group udp 53 TO dns-servers
        FROM test-group icmp 8 TO dns-servers
        '''
        expected = [{'destination': ['dns-servers'],
                     'proto': ['tcp'],
                     'range': [53],
                     'source': ['test-group']},
                    {'destination': ['dns-servers'],
                     'proto': ['udp'],
                     'range': [53],
                     'source': ['test-group']},
                    {'destination': ['dns-servers'],
                     'proto': ['icmp'],
                     'range': [8],
                     'source': ['test-group']}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_invalid_protocol(self):
        """
        The parser raises an error for invalid protocol specifiers.
        """
        input_text = '''
        FROM test-group invalid 22 TO test-group
        '''
        assert_raises(ParseError, self.parser.parse, input_text)

    def test_range_varref(self):
        """
        The parser properly parses variable references as ranges.
        """
        input_text = '''
        ping = 8:0
        FROM test-group icmp @ping TO test-group
        '''
        expected = [{'destination': ['test-group'],
                     'proto': ['icmp'],
                     'range': {'end': 0, 'start': 8},
                     'source': ['test-group']}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_range(self):
        """
        The parser properly parses range tokens as ranges.
        """
        input_text = '''
        FROM test-group icmp 8:0 TO test-group
        '''
        expected = [{'destination': ['test-group'],
                     'proto': ['icmp'],
                     'range': {'end': 0, 'start': 8},
                     'source': ['test-group']}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)


    def test_invalid_range(self):
        """
        The parser raises an error for invalid range specifiers.
        """
        input_text = '''
        FROM test-group icmp invalid TO test-group
        '''
        assert_raises(ParseError, self.parser.parse, input_text)

    def test_destination_varref(self):
        """
        The parser properly parses variable references as ranges.
        """
        input_text = '''
        dns-servers = 10.0.0.1, 10.0.0.2,
        FROM test-group tcp 53 TO @dns-servers
        '''
        expected = [{'destination': [IP('10.0.0.1'), IP('10.0.0.2')],
                     'proto': ['tcp'],
                     'range': [53],
                     'source': ['test-group']}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_destination_wildcard(self):
        """
        The parser properly parses '*' as a wild card destination.
        """
        input_text = '''
        GROUP test-group-1
        GROUP test-group-2
        FROM 0.0.0.0/0 tcp 22 TO *
        '''
        expected = [{'destination': set(['test-group-1', 'test-group-2']),
                     'proto': ['tcp'],
                     'range': [22],
                     'source': [IP('0.0.0.0/0')]}]
        result = self.parser.parse(input_text)['rules']
        assert_equal(result, expected)

    def test_undefined_variable(self):
        """
        The parser raises an error for undefined variables.
        """
        input_text = '''
        FROM @undefined tcp 22 TO test-group
        '''
        raise SkipTest('Broken test.')
        assert_raises(ParseError, self.parser.parse, input_text)
