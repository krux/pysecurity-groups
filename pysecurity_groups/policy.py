### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Policy functions for pysecurity-groups."""

from operator import concat

from util import expand_sources, rule_dict


POLICY_VARS = None
PROTO_SEPARATOR = ':'
RANGE_SEPARATOR = '-'
LIST_SEPARATOR = ','


def parse(config):
    """
    Parse the CONFIG and return a list of the rules it defines.

    Parsed rules are represented by dicts.
    """
    ### The parsing code doesn't use the CONFIG section; remove it so we don't
    ### have to special-case it.
    config.remove_section('CONFIG')

    ### Set up the variable mapping
    if config.has_section('VARIABLES'):
        global POLICY_VARS
        POLICY_VARS = parse_vars(config.items('VARIABLES'))
        config.remove_section('VARIABLES')

    return reduce(concat, [rules(group, config) for group in groups(config)])


def parse_vars(variables):
    """
    Given a list of un-expanded VARIABLES, return a dict mapping variable
    names to the expanded value of the variable as detailed in expand_value().
    """
    return dict([expand_value(varspec) for varspec in variables])


def expand_value(varspec):
    """
    Given VARSPEC, a tuple of the form (NAME, VALUE), return a tuple of the
    form (NAME, EXPANDED), where EXPANDED is a (python) list if VALUE
    specified a (text) list of values.
    """
    name, value = varspec
    if LIST_SEPARATOR in value:
        value = [val.strip() for val in value.split(LIST_SEPARATOR)]
    return (name, value)


def groups(policy):
    """
    Return an iterator over the groups defined by the policy. Group names are
    returned in canonical form as detailed in canonicalize_group().
    """
    return [canonicalize_group(group) for group
            in [section for section in policy.sections()
                if section not in ['GLOBAL', 'VARIABLES']]]


def canonicalize_group(group):
    """
    Given a group name GROUP, return the group name in canonical form.

    Canonical form is lowercase with white space trimmed from each end.
    """
    ### The GLOBAL group is a special case because it isn't actually a group,
    ### it defines the rules applied to all groups.
    if group == 'GLOBAL':
        return group
    return group.lower().strip()


def rules(group, policy):
    """
    Given a GROUP and a POLICY, parse the rules for that GROUP from the POLICY
    and return them (as a list of dicts). Rules which specify lists of sources
    or ports are expanded into multiple rules. Variables used by the rules are
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
                            in policy.items('GLOBAL') + policy.items(group)]])


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
    ### Check if the whole spec is a variable.
    spec = lookup(spec)

    ### Extract the protocol
    protocol, spec = spec.split(PROTO_SEPARATOR, 1)

    ### Call lookup again to see if the spec uses a variable after the
    ### protocol tag.
    spec = lookup(spec)

    if spec == '*':
        ### User wants to open all ports/types.
        return (protocol, protocol_glob(protocol))
    elif RANGE_SEPARATOR in spec:
        ### User wants to open a range of ports/types. Use lookup in case they
        ### used a variable for the endpoints.
        return (protocol, tuple([int(lookup(item)) for item
                              ### Limit the split to 1 because a range can
                              ### only have 2 endpoints.
                              in spec.split(RANGE_SEPARATOR, 1)]))
    elif LIST_SEPARATOR in spec:
        ### User wants to open a list of ports/types. Use lookup in case one
        ### of the items of the list is a variable.
        return (protocol, [int(lookup(item)) for item
                        in spec.split(LIST_SEPARATOR)])
    ### User wants to open a single port/type. Look it up in case it is a
    ### variable.
    return (protocol, int(lookup(spec)))


def parse_sources(sources):
    if LIST_SEPARATOR in sources:
        sources = [lookup(source) for source in sources.split(LIST_SEPARATOR)]
    else:
        sources = lookup(sources)
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
    if not is_variable(variable):
        return variable
    ### Strip the '@' for lookup.
    try:
        return POLICY_VARS[variable[1:].lower()]
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
