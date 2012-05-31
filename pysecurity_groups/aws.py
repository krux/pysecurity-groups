### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""AWS functions for pysecurity-groups."""

from ConfigParser import NoOptionError
from operator import concat

### The code which reads the boto configuration files only runs when you
### import boto, so even though we aren't using the module, we need to import
### it.
import boto
from boto.ec2 import connect_to_region
from boto.exception import BotoClientError, BotoServerError

from util import expand_sources, rule_dict


class AccountIDError(StandardError):
    """
    Error raised when no account ID is configured and the account ID cannot be
    queried from AWS.
    """
    pass

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
        ports_or_types = int(rule.from_port)
    else:
        ports_or_types = (int(rule.from_port), int(rule.to_port))
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


def account_id(config):
    """
    Given a CONFIG, return the account-id configuration value if it is set,
    otherwise query AWS for the account ID and raise an exception if one is
    not found.
    """
    try:
        account = config.get('CONFIG', 'account-id')
    except NoOptionError:
        account = None
        regions = [region.strip()
                   for region in config.get('CONFIG', 'regions').split(',')]
        while (account is None) and regions:
            region = regions.pop()
            try:
                group = connect_to_region(region).get_all_security_groups()[0]
                account = group.owner_id
            except (BotoClientError, BotoServerError):
                pass
        if account is None:
            raise AccountIDError()
    config.set('CONFIG', 'account-id', account)
    return account


def authorize(rule, owner):
    """
    Given a RULE dict and OWNER (an AWS account ID), call the correct
    authorization method based on whether the rule's source is a CIDR address
    or a security group.
    """
    conn = connect_to_region(rule['region'])
    if type(rule['port/type']) is tuple:
        from_port, to_port = rule['port/type']
    else:
        from_port = rule['port/type']
        to_port = from_port
    if '/' in rule['source']: ### source is a CIDR address
        return conn.authorize_security_group(rule['target'],
                                             ip_protocol=rule['protocol'],
                                             from_port=from_port,
                                             to_port=to_port,
                                             cidr_ip=rule['source'])
    return conn.authorize_security_group(rule['target'],
                                         src_security_group_name=rule['source'],
                                         src_security_group_owner_id=owner,
                                         ip_protocol=rule['protocol'],
                                         from_port=from_port,
                                         to_port=to_port)


def revoke(rule, owner):
    """
    Given a RULE dict and OWNER (an AWS account ID), call the correct
    de-authorization method based on whether the rule's source is a CIDR
    address or a security group.
    """
    conn = connect_to_region(rule['region'])
    if type(rule['port/type']) is tuple:
        from_port, to_port = rule['port/type']
    else:
        from_port = rule['port/type']
        to_port = from_port
    if '/' in rule['source']: ### source is a CIDR address
        return conn.revoke_security_group(rule['target'],
                                          ip_protocol=rule['protocol'],
                                          from_port=from_port,
                                          to_port=to_port,
                                          cidr_ip=rule['source'])
    return conn.revoke_security_group(rule['target'],
                                      src_security_group_name=rule['source'],
                                      src_security_group_owner_id=owner,
                                      ip_protocol=rule['protocol'],
                                      from_port=from_port,
                                      to_port=to_port)
