### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Parser for pysecurity-groups rules files."""

import ply.lex as lex
import ply.yacc as yacc
from IPy import IP
from pprint import pprint

###################################################################
############################## Lexer ##############################
###################################################################
RESERVED = {
    'FROM'  : 'FROM',
    'TO'    : 'TO',
    'GROUP' : 'GROUP',
}

tokens = [
    'ASSIGN',
    'ID',
    'CIDR',
    'PORT',
    'PROTO',
    'VARREF',
    ] + RESERVED.values()

literals = '*,'

t_ignore_COMMENT = r'\#.*'
t_ignore         = ' \t'

# Variable references are an @ sign followed by an identifier.
def t_VARREF(t):
    r'(?i)@[a-zA-Z][-\w]*'
    return t

# Protocol identifiers
def t_PROTO(t):
    r'(tcp|udp|icmp)'
    return t

# Variable assignment
def t_ASSIGN(t):
    r'(?i)([a-zA-Z][-\w]*)\s*='
    t.value = t.value.rstrip('=').strip()
    return t

# General identifiers
def t_ID(t):
    r'[a-zA-Z][-\w]*'
    t.type = RESERVED.get(t.value, 'ID')
    return t

# CIDR identifiers
def t_CIDR(t):
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))?\b'
    t.value = IP(t.value)
    return t

# Port identifiers
def t_PORT(t):
    r'[\d]+(:[\d]+)?'
    sep = ':'
    if sep in t.value:
        start, _, end = t.value.partition(sep)
        t.value = {'start': int(start),
                   'end': int(end)}
    else:
        t.value = int(t.value)
    return t

# Track line numbers
def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

# Error handling
def t_error(t):
    print "Illegal character '%s'" % t.value[0]
    t.lexer.skip(1)

LEXER = lex.lex()

####################################################################
############################## Parser ##############################
####################################################################
'''
line : assignment | groupspec | rulespec

assignment : ASSIGN expression

expression : expression ',' value
           | value

value : CIDR | '*' | ID | PORT | VARREF | PROTO
'''

_REF_CHAR = '@'
_SEP_CHAR = ','

class ParseError(Exception):
    pass

# Mapping of variable names
VARS = {}

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
    if not responds_to(thing, 'startswith'):
        message = 'Cannot create a variable reference from %r, no startswith() method!'
        message = message % thing
        raise ParseError(message)
    if thing.startswith(_REF_CHAR):
        return thing.lower()
    try:
        return _REF_CHAR + thing.lower()
    except TypeError:
        message = 'Cannot create a variable reference from %r, could not prepend %s!'
        message = message % (thing, _REF_CHAR)
        raise ParseError(message)

def p_policy(p):
    """
    policy : declarations
    """
    p[0] = p[1]

def p_declarations(p):
    """
    declarations :
                 | declarations declaration
    """
    p[0] = []
    if len(p) > 1 and p[1] and p[2]:
        p[0] = p[1] + [p[2]]

def p_declaration(p):
    """
    declaration : assignment
    """
    p[0] = p[1]

def p_assignment(p):
    """
    assignment : ASSIGN values
    """
    name  = as_ref(p[1])
    value = p[2]
    if name in VARS:
        message = 'Cannot re-assign variable %s on line %i!' % (name, p.lineno(1))
        raise ParseError(message)
    VARS[name] = value

def p_values_list(p):
    """
    values : values ',' value
    """
    p[0] = p[1]
    value = p[3]
    if not responds_to(value, '__iter__'):
        value = [value]
    if not responds_to(p[0], 'extend'):
        p[0] = [p[0]]
    p[0].extend(value)

def p_values(p):
    """
    values : values ','
           | value
    """
    p[0] = p[1]

def p_value_varref(p):
    """
    value : VARREF
    """
    value = VARS.get(as_ref(p[1]), None)
    if value:
        p[0] = value
    else:
        message = 'Undefined variable %s on line %i!' % (p[1], p.lineno(1))
        raise SyntaxError(message)

def p_value(p):
    """
    value : CIDR
          | '*'
          | ID
          | PORT
          | PROTO
    """
    p[0] = p[1]

def p_error(p):
    if p:
        print("Syntax error at '%s'" % p.value)
    else:
        print("Syntax error at EOF")

PARSER = yacc.yacc()

#####################################################################
############################## Testing ##############################
#####################################################################
if __name__ == '__main__':
    with open('../krux.conf', 'r') as policy:
        raw = policy.read()
        LEXER.input(raw)
        # for token in LEXER:
        #     print token
        PARSER.parse(raw,debug=1)
        pprint(VARS, indent=4)
