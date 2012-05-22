### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Policy functions for pysecurity-groups."""

from itertools import imap
from operator import concat


POLICY = None
PROTO_SEPARATOR = ':'
PROTO_INFO = {'tcp': {'name': 'ports',
                      'glob': (0,65535)},
              'icmp': {'name': 'types',
                       'glob': (-1,-1)}}
RANGE_SEPARATOR = '-'
LIST_SEPARATOR = ','


def canonicalize_group(group):
    """
    Given a group name GROUP, return the group name in canonical form.
    """
    ### The GLOBAL group is a special case because it isn't actually a group,
    ### it defines the rules applied to all groups.
    if group == 'GLOBAL': return group
    return group.lower().strip()


def groups():
    """
    Return an iterator over the groups defined by the policy. Group names are
    in canonical form.
    """
    for group in imap(canonicalize_group,
                      filter(lambda g: g != 'GLOBAL', POLICY.sections())):
        yield group


def proto_spec_name(proto):
    return PROTO_INFO[proto]['name']


def parse_spec(spec):
    """
    Given a human-friendly rule specifier, return a machine-friendly tuple
    expanded from that specifier.

    The human-frendly rule specifier is of the form <protocol>:<spec>, where
    <protocol> is 'tcp' or 'icmp'; <spec> can be one of:

    * A '*' indicating all ports (tcp) or types (icmp).
    * A range specifying the beginning and end of a range of ports (tcp) or types(icmp).
    * A comma-separated list of ports (tcp) or types (icmp).
    * A single port (tcp) or type (icmp).

    The machine-friendly tuple is of the form (<protocol>, <name>, <spec>)
    where <protocol> is the same as above, <name> is one of 'ports' (tcp) or
    'types' (icmp), and <spec> is either an integer specifying a port (tcp) or
    type (icmp), a tuple containing integers specifying the start and end
    points of a range of ports (tcp) or types (icmp), or a list of integers
    specifying ports (tcp) or types (icmp).
    """
    proto, spec = spec.split(PROTO_SEPARATOR, 1)
    name = proto_spec_name(proto)
    if spec == '*':
        return (proto, name, PROTO_INFO[proto]['glob'])
    elif RANGE_SEPARATOR in spec:
        return (proto, name, tuple([int(item) for item
                                    in spec.split(RANGE_SEPARATOR, 1)]))
    elif LIST_SEPARATOR in spec:
        return (proto, name, [int(item) for item
                              in spec.split(LIST_SEPARATOR)])
    else:
        return (proto, name, int(spec))


def rule_dict(source, target, proto, name, spec):
    return {'source': source,
            'target': target,
            'protocol': proto,
            name: spec}


def parse_rule(rule):
    """
    Given a rule specifier of the form (<target>, <source>, <spec>), return a
    dictionary representing that rule, with <spec> expanded according to the
    rules detailed in parse_spec().
    """
    target, source, spec = rule
    proto, name, spec = parse_spec(spec)
    return rule_dict(source, target, proto, name, spec)


def expand_rule(rule):
    """
    Given a rule specifier (as a dict), return a list of rules that specifier
    expands to. Only rules specifying a list of ports/types are expanded.
    """
    name = proto_spec_name(rule['protocol'])
    if type(rule[name]) in [int, tuple]:
        return [rule]
    else:
        return [rule_dict(rule['source'],
                          rule['target'],
                          rule['protocol'],
                          name,
                          port) for port in rule[name]]


def rules(group):
    """
    Given a GROUP, parse the rules for that group from the policy and return
    them (as a list of dicts). Rules which specify lists of ports are expanded
    into multiple rules.
    """
    if not POLICY.has_section(group):
        raise NameError('No group %s defined in policy!' % group)
    ### This outer comprehension gives us a list of dicts representing the
    ### parsed rules for the group.
    return reduce(concat, [expand_rule(parse_rule(rule)) for rule in
                           ### This inner comprehension gives us a list of
                           ### tuples (group, source, rule) where group is the
                           ### destination group (the group the rule will be
                           ### applied to), source is the source group or CIDR
                           ### address, and rule is a tuple of (source,
                           ### rulespec).
                           [(group, source, rule)
                            for source, rule
                            in POLICY.items('GLOBAL') + POLICY.items(group)]])


def parse(config):
    global POLICY
    if POLICY is None:
        POLICY = config

    return reduce(concat, [rules(group) for group in groups()])
