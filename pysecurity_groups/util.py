### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Utility functions for pysecurity-groups."""


def format_headers(headers, hmap):
    """
    Given a list of HEADERS and an HMAP mapping the headers to their
    attributes, return a formatted header string.
    """
    return ''.join([header.ljust(hmap[header]['width'])
                    for header in headers])


def format_rule(rule, headers, hmap):
    """
    Given a RULE, a list of HEADERS, and an HMAP mapping the headers to their
    attributes, return a formatted rule string.
    """
    return ''.join([format_for_report(rule[key]).ljust(width)
                    for header, width, key
                    in [(header, hmap[header]['width'], hmap[header]['key'])
                        for header in headers]])


def header_widths(hmap, rules):
    """
    Given an HMAP mapping headers to their attributes, and a set of rules,
    return an updated HMAP containing the column widths for each header
    required to accommodate the longest rule value for that column.
    """
    for header in hmap:
        ### Calculate the width of each column.
        hmap[header]['width'] = column_width(header, rules, hmap[header]['key'])
    return hmap


def column_width(header, rules, key):
    """
    Return the width of column needed to print the longest of either HEADER or
    the longest value of KEY in RULES.
    """
    val_width = len(sorted([format_for_report(rule[key])
                            for rule in rules], key=len)[-1])
    ### Pad the widths with 2 spaces.
    return max(val_width + 2, len(header) + 2)


def format_for_report(value):
    """
    Given a rule VALUE, return that value formatted for reporting. Range
    tuples are formatted as 'BEGINNING-END', other values are simply returned
    as strings.
    """
    if type(value) is tuple:
        return '%s-%s' % value
    return str(value)


def rule_dict(sources, target, protocol, spec):
    """
    Return a dictionary representing a rule.

    * SOURCES is the list of sources for this rule. These can be security
      group names or CIDR addresses.
    * TARGET is the name of the security group this rule should be applied to.
    * PROTOCOL is 'tcp', 'icmp', or 'udp'
    * SPEC is the list of ports (tcp/udp) or types (icmp) this rule
      allows.
    """
    return {'sources': sources,
            'target': target,
            'protocol': protocol,
            'ports_or_types': spec}


def expand_sources(rule):
    """
    Given a RULE (as a dict) return a list of rules, one for each source.
    """
    return [rule_dict(source,
                      rule['target'],
                      rule['protocol'],
                      rule['ports_or_types']) for source in rule['sources']]
