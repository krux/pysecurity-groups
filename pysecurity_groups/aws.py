### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""AWS functions for pysecurity-groups."""

from operator import concat

### The code which reads the boto configuration files only runs when you
### import boto, so even though we aren't using the module, we need to import
### it.
import boto
from boto.ec2 import connect_to_region

from util import expand_sources, rule_dict


def policy(config):
    """
    For each region from CONFIG, fetch the security groups and rules. Return
    them as rule dicts.
    """
    regions = [region.strip()
               for region in config.get('CONFIG', 'regions').split(',')]
    return reduce(concat, [rules(region) for region in regions])


def rules(region):
    """
    Given a REGION, return the live rules for that REGION.
    """
    groups = connect_to_region(region).get_all_security_groups()
    return [dict([('region', region)] + rule.items())
            for rule in reduce(concat, [expand_rules(group)
                                        for group in groups])]


def expand_rules(group):
    """
    Given a GROUP, return a list of rules for that group, with each rule fully
    expanded.
    """
    return reduce(concat, [expand_rule(group, rule) for rule in group.rules],
                  [])


def expand_rule(group, rule):
    """
    Given a group and a rule, return a list of expanded rules, with a rule for
    each distinct source or port in a list of ports.
    """
    if rule.from_port == rule.to_port:
        ports_or_types = rule.from_port
    else:
        ports_or_types = (rule.from_port, rule.to_port)
    return expand_sources(rule_dict(parse_grants(rule.grants),
                                    group.name,
                                    rule.ip_protocol,
                                    ports_or_types))


def parse_grants(grants):
    """
    Translate the EC2 GRANTS into our internal format.
    """
    return concat([grant.cidr_ip for grant in grants
                   if grant.cidr_ip is not None],
                  [grant.name for grant in grants
                   if grant.name is not None])


def groups(region):
    """
    Given a REGION, return the list of all security groups defined in that
    REGION.
    """
    return [group.name for group in
            connect_to_region(region).get_all_security_groups()]
