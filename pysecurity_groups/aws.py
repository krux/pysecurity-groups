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
    groups = connect_to_region(region).get_all_security_groups()
    return [dict([('region', region)] + rule.items())
            for rule in reduce(concat, [expand_rules(group)
                                        for group in groups])]


def expand_rules(group):
    return reduce(concat, [expand_rule(group, rule) for rule in group.rules])


def expand_rule(group, rule):
    if rule.from_port == rule.to_port:
        ports_or_types = rule.from_port
    else:
        ports_or_types = (rule.from_port, rule.to_port)
    p = parse_grants(rule.grants)
    return expand_sources(rule_dict(p,
                                    group.name,
                                    rule.ip_protocol,
                                    ports_or_types))


def parse_grants(grants):
    return concat([grant.cidr_ip for grant in grants
                   if grant.cidr_ip is not None],
                  [grant.name for grant in grants
                   if grant.name is not None])
