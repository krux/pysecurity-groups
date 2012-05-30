### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Policy functions for pysecurity-groups."""

from operator import concat
import re

from util import expand_sources, rule_dict


POLICY = None
POLICY_VARS = {}
VAR_REGEX = re.compile(r'@[\w-]*')
PROTO_SEPARATOR = ':'
RANGE_SEPARATOR = '-'
LIST_SEPARATOR = ','
SPECIAL_CONFIG_SECTIONS = ['CONFIG', 'GLOBAL', 'VARIABLES']


def parse(config):
    """
    Parse the CONFIG and return a list of the rules it defines.

    Parsed rules are represented by dicts.
    """
    ### Set up the variable mapping
    if config.has_section('VARIABLES'):
        global POLICY_VARS
        POLICY_VARS = dict([(name.translate(None, '\n'),
                             value.translate(None, '\n'))
                            for name, value in config.items('VARIABLES')])
        config.remove_section('VARIABLES')

    ### Set up the global policy variable
    global POLICY
    POLICY = config

    return reduce(concat, [rules(group) for group in groups(config)])


def groups(policy):
    """
    Return the set of groups defined by the POLICY.
    """
    return set([group for group
                in [section for section in policy.sections()
                    if section not in SPECIAL_CONFIG_SECTIONS]])


def rules(group):
    """
    Given a GROUP parse the rules for that GROUP from the policy and return
    them (as a list of dicts). Rules which specify lists of sources or ports
    are expanded into multiple rules. Variables used by the rules are
    expanded.
    """
    ### This outer comprehension gives us a list of lists of dicts
    ### representing the parsed rules for the group. Then reduce(concat, ...)
    ### concatenates the lists into a single list of rules.
    return reduce(concat, [expand_rule(parse_rule(rule)) for rule in
                           ### This inner comprehension gives us a list of
                           ### tuples (group, source, rule) where group is the
                           ### destination group (the group the rule will be
                           ### applied to), source is the source group or CIDR
                           ### address, and rule is a tuple of (source,
                           ### rulespec).
                           [(group, source, rule)
                            for source, rule
                            in expand_variables(POLICY.items('GLOBAL')) +
                            expand_variables(POLICY.items(group))]])


def expand_variables(items):
    """
    Given a list of ITEMS which are tuples of the form (SOURCE, TARGET),
    expand all the variables in SOURCE and TARGET and return a list of tuples
    with the variables expanded.
    """
    return [expand_vars(source, target) for source, target in items]


def expand_vars(source, target):
    """
    Given a SOURCE and a TARGET, expand the variables in SOURCE and TARGET and
    return a tuple of the expanded strings.
    """
    return (reduce(replace_var, VAR_REGEX.findall(source), source),
            reduce(replace_var, VAR_REGEX.findall(target), target))


def replace_var(varstring, variable):
    """
    Given a VARSTRING and a VARIABLE, return a string with all instances of
    VARIABLE in VARSTRING replaced by their value.
    """
    return re.sub(re.compile(variable + r'\b([^-]|$)'),
                  lookup(variable) + r'\1', varstring)


def parse_rule(rule):
    """
    Given a RULE specifier of the form (TARGET, SOURCES, SPEC), return a
    dictionary representing that rule, with SPEC expanded according to the
    rules detailed in parse_spec().
    """
    target, sources, spec = rule
    sources = parse_sources(sources)
    protocol, spec = parse_spec(spec)
    return rule_dict(sources, target, protocol, spec)


def parse_spec(spec):
    """
    Given an un-expanded rule SPEC, return a tuple expanded from that
    specifier.

    SPEC is of the form PROTOCOL:SPEC, where PROTOCOL is 'tcp', 'udp', or
    'icmp' and SPEC can be one of:

    * A '*' indicating all ports (tcp/udp) or types (icmp).
    * A range specifying the beginning and end of a range of ports (tcp/udp)
      or types(icmp).
    * A comma-separated list of ports (tcp/udp) or types (icmp).
    * A single port (tcp/udp) or type (icmp).
    * A variable containing one of the above.

    The expanded tuple is of the form (PROTOCOL, SPEC) where PROTOCOL is the
    same as above, SPEC is either an integer specifying a port (tcp/udp) or
    type (icmp), a tuple containing integers specifying the start and end
    points of a range of ports (tcp/udp) or types (icmp), or a list of
    integers specifying ports (tcp/udp) or types (icmp).
    """
    ### Extract the protocol
    protocol, spec = spec.split(PROTO_SEPARATOR, 1)

    if spec == '*':
        ### User wants to open all ports/types.
        return (protocol, protocol_glob(protocol))
    elif RANGE_SEPARATOR in spec:
        ### User wants to open a range of ports/types.
        return (protocol, tuple([int(item) for item
                              ### Limit the split to 1 because a range can
                              ### only have 2 endpoints.
                              in spec.split(RANGE_SEPARATOR, 1)]))
    elif LIST_SEPARATOR in spec:
        ### User wants to open a list of ports/types.
        return (protocol, [int(item) for item in spec.split(LIST_SEPARATOR)])
    ### User wants to open a single port/type.
    return (protocol, int(spec))


def parse_sources(sources):
    """
    Given a SOURCES string, expand all variables and split it into a list if
    it is in list form.
    """
    if sources == '*':
        sources = list(groups(POLICY))
    if LIST_SEPARATOR in sources:
        sources = [source.strip() for source in sources.split(LIST_SEPARATOR)]
    if type(sources) is not list:
        ### Pack single sources in a list so I don't have to special-case the
        ### expansion code.
        sources = [sources]
    return sources


def lookup(variable):
    """
    Given a VARIABLE name from the policy, return the value of that
    variable. Given any other value, return it unchanged.
    """
    variable = variable.lower()
    if not is_variable(variable):
        return variable
    try:
        ### Strip the '@' for lookup.
        return POLICY_VARS[variable[1:]]
    except KeyError:
        raise KeyError('No such variable %s defined in policy!' % variable)


def is_variable(thing):
    """
    Return True if THING is a string that starts with '@'.
    """
    return hasattr(thing, 'startswith') and thing.startswith('@')


def protocol_glob(protocol):
    """
    Return the appropriate wildcard for the PROTOCOL. For tcp/udp, this
    is (1, 65535), for icmp, this is -1.
    """
    return {'tcp': (1, 65535), 'udp': (1, 65535), 'icmp': -1}[protocol]


def expand_rule(rule):
    """
    Given a RULE (as a dict), return a list of rules that RULE expands to.
    """
    return reduce(concat, [expand_spec(expanded)
                           for expanded in expand_sources(rule)])


def expand_spec(rule):
    """
    Given a RULE (as a dict) that specifies a list of ports/types, return a
    list of rules, one for each port/type.
    """
    if type(rule['ports_or_types']) in [int, tuple]:
        return [rule]
    return [rule_dict(rule['sources'],
                      rule['target'],
                      rule['protocol'],
                      port) for port in rule['ports_or_types']]
