### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Parser for pysecurity-groups rules files."""

import ply.lex as lex
import ply.yacc as yacc
from IPy import IP


###############################################################################
######################### Utility classes / functions #########################
###############################################################################

class ParseError(Exception):
    """
    Exceptions raised during the parsing process.
    """
    pass


def responds_to(thing, method):
    """
    Returns True if THING has an attribute METHOD and that attribute is
    callable.
    """
    return callable(getattr(thing, method, None))


def as_ref(thing):
    """
    Converts THING to a variable reference by prepending the variable
    reference character.

    Raises a ParseError if it is unable to create a variable reference.
    """
    ref_char = '@'
    if not responds_to(thing, 'startswith'):
        message = 'Cannot create a variable reference from %r, '
        message += 'no startswith() method!'
        message = message % thing
        raise ParseError(message)
    if thing.startswith(ref_char):
        return thing.lower()
    try:
        return ref_char + thing.lower()
    except TypeError:
        message = 'Cannot create a variable reference from %r, '
        message += 'could not prepend %s!'
        message = message % (thing, ref_char)
        raise ParseError(message)


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


###############################################################################
#################################### Lexer ####################################
###############################################################################

class SGLexer(object):
    # pylint: disable=C0103,R0201
    """
    Lexer for the pysecurity-groups policy file format.
    """
    # Reserved words. Per the PLY documentation: "To handle reserved words,
    # you should write a single rule to match an identifier and do a special
    # name lookup in a function. This approach greatly reduces the number of
    # regular expression rules and is likely to make things a little faster."
    _reserved = {
        'FROM':  'FROM',
        'TO':    'TO',
        'GROUP': 'GROUP',
        'tcp':   'PROTO',
        'udp':   'PROTO',
        'icmp':  'PROTO',
    }

    # List of token types. This is required by ply.lex in order to determine
    # which tokens are valid. The variable *must* be named 'tokens' because of
    # magic :-(
    tokens = uniq([
        'ASSIGN',
        'ID',
        'CIDR',
        'RANGE',
        'VARREF',
    ] + _reserved.values())

    # Literal characters that will be treated as tokens. Literals must be
    # single characters only; if you want a multiple-character "literal"
    # define it as either a regex or a function (see below). The variable
    # *must* be named 'literals' because of magic :-(
    literals = '*,'

    def __init__(self, data, **kwargs):
        """
        Initialize the lexer.
        """
        self.lexer = lex.lex(module=self, **kwargs)
        self.lexer.input(data)

    def __iter__(self):
        """
        Proxy to the lexer for iteration.
        """
        return self.lexer

    #############################
    # Regex Snippets For Tokens #
    #############################

    # Identifiers begin with a letter and are made up of word components (\w)
    # and dashes (-).
    _identifier_re = r'[a-zA-Z][-\w]*'

    #####################
    # Token Definitions #
    #####################

    ### Note that the ORDER of definition of the rules below matters.
    ###
    ### Rules are added in the following order:
    ###
    ### 1. All tokens defined by functions are added in the same order as they
    ###    appear in the lexer file.
    ###
    ### 2. Tokens defined by regexes are added next by sorting them in order
    ###    of decreasing regular expression length (longer expressions are
    ###    added first).

    # Discard comments and whitespace. These rules are defined as simple
    # regular expressions because there is no additional processing/action
    # required to tokenize them.
    t_ignore_COMMENT = r'\#.*'
    t_ignore = ' \t'

    # Variable references are an @ sign followed by an identifier. The token
    # value will the matched string representing the variable reference.
    t_VARREF = r'(?i)@' + _identifier_re

    # Variable assignments are an identifier followed by (optional)
    # whitespace, followed by an equals sign (=). We use the @TOKEN decorator
    # here so we can build the regular expression out of components (you can't
    # use expressions in a docstring).
    #
    # We use the function form of rule specification in order to strip the
    # equals sign from the resulting token value, which will be a string
    # representing the variable name we're assigning to.
    @lex.TOKEN(r'(?i)' + _identifier_re + r'\s*=')
    def t_ASSIGN(self, t):      # pylint: disable=C0111
        t.value = t.value.rstrip('=').strip()
        return t

    # General identifiers and reserved words.
    #
    # We check to see if the token is a reserved word, if it isn't, then we
    # use the generic 'ID' for the token type. The token value will be a
    # string representing the matched reserved word, or the matched
    # identifier.
    @lex.TOKEN(r'(?i)' + _identifier_re)
    def t_ID(self, t):      # pylint: disable=C0111
        t.type = self._reserved.get(t.value, 'ID')
        return t

    # CIDR identifiers. The token value will be an IP object.
    def t_CIDR(self, t):
        # This is a beast. Cobbled together from google searches.
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))?\b'
        t.value = IP(t.value)
        return t

    # Range tokens represent TCP ports or ICMP types/codes. They can be an
    # asterisk, a single integer representing the port or type, or a
    # colon-separated string representing start_port:end_port or type:code.
    #
    # The token value will be either '*', a dict with 'start' and 'end' keys
    # representing a range, or an int representing the port or type.
    def t_RANGE(self, t):
        r'\*|([\d]+(:[\d]+)?)'
        if '*' in t.value and len(t.value) > 1:
            message = 'Invalid use of * in a range specifier at line %i!'
            raise ParseError(message % t.lexer.lineno)
        elif t.value == '*':
            return t
        sep = ':'
        if sep in t.value:
            start, _, end = t.value.partition(sep)
            t.value = {'start': int(start),
                       'end': int(end)}
        else:
            t.value = int(t.value)
        return t

    # Track line numbers by counting occurences of newlines. Since we do not
    # return a token, the newlines will be discarded.
    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    # Rudimentary error handling. Print a message and then skip a character.
    def t_error(self, t):      # pylint: disable=C0111
        print "Illegal character '%s'" % t.value[0]
        t.lexer.skip(1)


################################################################################
#################################### Parser ####################################
################################################################################

class SGParser(object):
    # pylint: disable=C0103,R0201
    """
    Parser for the pysecurity-groups policy file format.
    """
    def __init__(self, lexer, *args, **kwargs):
        """
        Initialize the parser.
        """
        self.lexer = lexer
        self.tokens = lexer.tokens
        self._vars = {}
        self._groups = set()
        self.parser = yacc.yacc(module=self, *args, **kwargs)

    def parse(self, *args, **kwargs):
        """
        Proxy to the parser's parse method.
        """
        return {'groups': self._groups,
                'rules': self.parser.parse(*args, **kwargs)}

    def resolve(self, name, p):
        """
        Resolve a VARREF to its value.
        """
        try:
            return self._vars[name]
        except KeyError:
            message = 'Undefined variable %s on line %i!' % (p[1], p.lineno(1))
            raise SyntaxError(message)

    ################
    # Parser Rules #
    ################

    ### Parser rules are defined as methods prefixed with 'p_'. The docstring
    ### is a psuedo-EBNF description of the part of the language that will be
    ### matched by the rule. Whatever is in p[0] after the rule is processed
    ### will be stored as the "value" of that rule.

    # A policy is a list of declarations. It is either empty, or a policy
    # followed by a single declaration. (The reader will note a fairly
    # traditional recursive definition of a list here...)
    def p_policy(self, p):
        """
        policy :
                     | policy declaration
        """
        if len(p) <= 1:         # Empty policy
            p[0] = []
        elif responds_to(p[1], 'extend'):
            # Append declaration values to the current policy.
            p[1].extend(p[2])
            p[0] = p[1]

    # A declaration can be an assignment, a groupspec, or a rulespec.
    def p_declaration(self, p):
        """
        declaration : assignment
                    | groupspec
                    | rulespec
        """
        p[0] = p[1]

    # An assignment is an ASSIGN token (whose value is the variable name we're
    # assigning to) followed by values. Assignment doesn't result in a parsing
    # value, but we set the "result" to an empty list to make it consistent
    # with how we'll be handling groupspecs and rulespecs higher up the parse
    # tree. (Basically, we're extending the top-level "policy", which is a
    # list; the empty assignment "disappears".)
    def p_assignment(self, p):
        """
        assignment : ASSIGN values
        """
        name = as_ref(p[1])
        if name in self._vars:
            message = 'Cannot re-assign variable %s on line %i!'
            message = message % (name, p.lineno(1))
            raise ParseError(message)
        self._vars[name] = p[2]
        p[0] = []

    # A groupspec is a GROUP token followed by an ID.
    def p_groupspec(self, p):
        """
        groupspec : GROUP ID
        """
        self._groups.add(p[2])
        p[0] = []

    # A rulespec is a FROM token, followed by a source, a PROTO token, a RANGE
    # token, a TO token, and an ID.
    def p_rulespec(self, p):
        """
        rulespec : FROM source protocol range TO destination
        """
        if p[6] == '*':
            p[6] = self._groups
        p[0] = {'source': p[2],
                'proto': p[3],
                'range': p[4],
                'destination': p[6]}
        for key, value in p[0].iteritems():
            p[0][key] = wrap(value)
        p[0] = [p[0]]

    ### The next two parsing rules are related. PLY allows you to split
    ### parsing rules up to avoid huge conditional trees. It makes sense to
    ### group together rules which have the same structure; the first rule
    ### deals with the case of multiple values, the second deals with trailing
    ### commas and single values.

    # A list of values (for assignment) is a list of values followed by a
    # literal comma, followed by a value... (see next rule)
    def p_values_list(self, p):
        """
        values : values ',' value
        """
        p[0] = p[1]
        value = p[3]
        # Wrapping atomic values again.
        if not responds_to(value, '__iter__'):
            value = wrap(value)
        # Again, we need to make sure p[0] is extendable before we try to
        # extend it. If it is not, we wrap it in a list.
        if not responds_to(p[0], 'extend'):
            p[0] = [p[0]]
        p[0].extend(value)

    # (see previous rule) ... or a list of values followed by a literal comma,
    # or a single value.
    def p_values(self, p):
        """
        values : values ','
               | value
        """
        p[0] = p[1]

    ### End "values" rules

    ### The next two parsing rules are also related. The first rule deals with
    ### variable references, which require processing; the second deals with
    ### other "value" tokens, which do not.

    # A value can be a variable reference, in which case we look up the
    # variable and substitute its value... (see next rule)
    def p_value_varref(self, p):
        """
        value : VARREF
        """
        p[0] = self.resolve(as_ref(p[1]), p)

    # (see previous rule) ... or a value can be one of: a CIDR, a literal
    # asterisk, an ID, a RANGE, or a PROTO.
    def p_value(self, p):
        """
        value : CIDR
              | '*'
              | ID
              | RANGE
              | PROTO
        """
        p[0] = p[1]

    ### End "value" rules

    ### Begin "source" rules

    # A source can be a variable reference, in which case we look up the
    # variable and substitute its value... (see next rule)
    def p_source_varref(self, p):
        """
        source : VARREF
        """
        p[0] = self.resolve(as_ref(p[1]), p)

    # (see previous rule) ... or a literal asterisk, a CIDR, or an ID.
    def p_source(self, p):
        """
        source : '*'
               | CIDR
               | ID
        """
        p[0] = p[1]

    ### End "source" rules

    ### Begin "protocol" rules

    # A protocol can be a variable reference, in which case we look up the
    # variable and substitute its value... (see next rule)
    def p_protocol_varref(self, p):
        """
        protocol : VARREF
        """
        p[0] = self.resolve(as_ref(p[1]), p)

    # (see previous rule) ... or a PROTO token.
    def p_protocol(self, p):
        """
        protocol : PROTO
        """
        p[0] = p[1]

    ### End "protocol" rules

    ### Begin "range" rules

    # A range can be a variable reference, in which case we look up the
    # variable and substitute its value... (see next rule)
    def p_range_varref(self, p):
        """
        range : VARREF
        """
        p[0] = self.resolve(as_ref(p[1]), p)

    # (see previous rule) ... or a RANGE token.
    def p_range(self, p):
        """
        range : RANGE
        """
        p[0] = p[1]

    ### End "range" rules

    ### Begin destination rules

    # A value can be a variable reference, in which case we look up the
    # variable and substitute its value... (see next rule)
    def p_destination_varref(self, p):
        """
        destination : VARREF
        """
        p[0] = self.resolve(as_ref(p[1]), p)

    # (see previous rule) ... or a literal asterisk, or an ID.
    def p_destination(self, p):
        """
        destination : '*'
                    | ID
        """
        p[0] = p[1]

    ### End "destination" rules

    # If we encounter a parsing error, print an error message.
    #
    # XXX: Replace this with logging.
    def p_error(self, p):      # pylint: disable=C0111
        if p:
            print("Syntax error at '%s'" % p.value)
        else:
            print("Syntax error at EOF")
