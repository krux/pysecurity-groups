### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Command line interface for pysecurity-groups."""

import ConfigParser
import errno
from operator import itemgetter
import sys

from argparse import ArgumentParser
### The code which reads the boto configuration files only runs when you
### import boto, so even though we aren't using the module, we need to import
### it to load credentials, etc.
import boto
from boto.ec2 import connect_to_region
from boto.exception import BotoClientError, BotoServerError

import aws as aws
import policy as policy
import report as report
import util as util


if __name__ == '__main__':
    sys.exit(main())


def main():
    """
    Entry point for the pysecurity_groups CLI.
    """
    args = get_parser().parse_args()
    config = get_config(args)

    ### The reporting functions use print statements. If you pipe the output
    ### of this script to, for example, less, and quit before all the output
    ### is consumed, the print statements will raise an IOError indicating a
    ### broken pipe. We deal with that here.
    try:
        args.dispatch_fn(config, args)
    except IOError, exc:
        if exc.errno == errno.EPIPE:
            sys.exit(0)
        else:
            raise exc
    except KeyboardInterrupt:
        print 'Interrupted'
        sys.exit(255)


def get_config(args):
    """
    Parse the configuration file and return a ConfigParser object.
    """
    config = ConfigParser.SafeConfigParser()
    config.read(args.config)
    ### Get the regions. Prefer regions specified on the command line, then
    ### regions specified in the config file. If neither is provided, use a
    ### sensible default.
    if args.region is None:
        ### No regions were specified on the command line, so try loading them
        ### from the config file.
        try:
            config.get('CONFIG', 'regions')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            ### No regions on the command line, and none in the config file,
            ### so set a sane default.
            if not config.has_section('CONFIG'):
                config.add_section('CONFIG')
            config.set('CONFIG', 'regions', 'us-east-1')
    else:
        config.set('CONFIG', 'regions', ','.join(args.region))
    return config


def get_parser():
    """
    Return a parser for the command-line arguments.
    """
    ##############################################
    ### Top-level parser and global arguments. ###
    ##############################################
    parser = ArgumentParser(description="""Command-line utility for working
                            with EC2 security groups in bulk.""")
    parser.add_argument('-c', '--config', help="""Path to the security-groups
                        configuration file.  Default: %(default)s.""",
                        default='/etc/security-groups/security-groups.conf')
    parser.add_argument('-r', '--region', help="""Region to manage security
                        groups in. Can be specified multiple times. Default:
                        us-east-1""", action='append')
    parser.add_argument('--no-headers', help="""Don't output header lines.""",
                        action='store_false', dest='headers', default=True)
    parser.add_argument('--debug', help="""Print exceptions.""",
                        action='store_true', default=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--groups-only', help="""Only report/operate on
                        security groups, not rules.""", action='store_true',
                        default=False)
    group.add_argument('--rules-only', help="""Only report/operate on security
                       rules, not groups. NOTE: This can lead to errors if
                       your groups are not already correctly defined in AWS.""",
                       action='store_true', default=False)

    ##########################################
    ### Sub-command parsers and arguments. ###
    ##########################################
    subparsers = parser.add_subparsers(title='Sub-Commands',
                                       description='Valid sub-commands:')

    ### 'policy' subcommand
    policy_parser = subparsers.add_parser('policy', help="""Generate a report
                                          detailing your desired groups/rules
                                          as parsed by this command.""")
    policy_parser.set_defaults(dispatch_fn=policy_report)

    ### 'aws-policy' subcommand
    aws_policy_parser = subparsers.add_parser('aws-policy', help="""Generate a
                                              report detailing your current
                                              groups/rules as reported by the
                                              AWS API.""")
    aws_policy_parser.set_defaults(dispatch_fn=aws_policy)

    ### 'diff' subcommand
    diff_parser = subparsers.add_parser('diff', help="""Generate a report
                                        showing the differences between your
                                        desired groups/rules and your current
                                        groups/rules.""")
    diff_parser.set_defaults(dispatch_fn=diff)

    ### 'sync' subcommand
    sync_parser = subparsers.add_parser('sync', help="""Synchronize
                                        groups/rules with your configured
                                        policy. Adds new groups/rules and
                                        REMOVES groups/rules not defined in
                                        the configuration file.""")
    sync_parser.set_defaults(dispatch_fn=sync)

    ### 'update' subcommand
    update_parser = subparsers.add_parser('update', help="""Update
                                          groups/rules to match your
                                          configured policy. Adds new
                                          groups/rules, but does NOT remove
                                          groups/rules that are not defined in
                                          the configuration file.""")
    update_parser.set_defaults(dispatch_fn=update)

    return parser


def policy_report(config, args):
    """
    Generate a report detailing your desired groups/rules as parsed by this
    command.
    """
    regions = util.regions(config)
    region_width = report.column_width(['REGION'] + regions)
    if not args.rules_only:
        if args.headers:
            print 'REGION'.ljust(region_width) + 'GROUP'
        for region in regions:
            for group in policy.groups(config):
                print region.ljust(region_width) + group
    if not args.groups_only:
        headers = ['REGION', 'SOURCE', 'TARGET', 'PROTOCOL', 'PORT/TYPE']
        ### Every rule in the policy, duplicated to each region we're
        ### managing, sorted by region.
        ###
        ### dict([('region', region)] + rule.items()) adds the 'region' key to
        ### the rule (which is stored as a dict) without updating it in-place.
        rules = [dict([('region', region)] + rule.items())
                 for rule in policy.parse(config)
                 for region in regions]
        ### The inner list comprehension gives us a list of the data values
        ### from the rule dicts corresponding to the header. So, when header
        ### is 'SOURCE', the inner comprehension gives us a list of values of
        ### rule['source'] for every rule. To this list we pre-pend the header
        ### itself so the label width is accounted for in the calculation of
        ### the column width.
        ###
        ### The outer list comprehension repeats the above for each header.
        widths = report.column_widths([[header] +
                                       [rule[header.lower()]
                                        for rule in rules]
                                       for header in headers])
        if args.headers:
            print ''.join([header.ljust(widths[index])
                           for index, header in enumerate(headers)])
        for rule in sorted(rules, key=itemgetter('region')):
            print ''.join([report.format(rule[hdr.lower()]).ljust(widths[index])
                           for index, hdr in enumerate(headers)])


def aws_policy(config, args):
    """
    Generate a report detailing your current groups/rules as reported by the
    AWS API.
    """
    regions = util.regions(config)
    region_width = report.column_width(['REGION'] + regions)
    if not args.rules_only:
        if args.headers:
            print 'REGION'.ljust(region_width) + 'GROUP'
        for region in regions:
            for group in aws.groups(region):
                print region.ljust(region_width) + group
    if not args.groups_only:
        headers = ['REGION', 'SOURCE', 'TARGET', 'PROTOCOL', 'PORT/TYPE']
        rules = aws.policy(config)
        ### The inner list comprehension gives us a list of the data values
        ### from the rule dicts corresponding to the header. So, when header
        ### is 'SOURCE', the inner comprehension gives us a list of values of
        ### rule['source'] for every rule. To this list we pre-pend the header
        ### itself so the label width is accounted for in the calculation of
        ### the column width.
        ###
        ### The outer list comprehension repeats the above for each header.
        widths = report.column_widths([[header] +
                                       [rule[header.lower()]
                                        for rule in rules]
                                       for header in headers])
        if args.headers:
            print ''.join([header.ljust(widths[index])
                           for index, header in enumerate(headers)])
        for rule in rules:
            print ''.join([report.format(rule[hdr.lower()]).ljust(widths[index])
                           for index, hdr in enumerate(headers)])


def diff(config, args):
    """
    Generate a report showing the differences between your desired
    groups/rules and your current groups/rules.
    """
    regions = util.regions(config)
    if not args.rules_only:
        policy_groups = dict([(region, set(policy.groups(config)))
                              for region in regions])
        aws_groups = dict([(region, set(aws.groups(region)))
                           for region in regions])
        all_groups = reduce(lambda a, b: a.union(b),
                            [policy_groups[region].union(aws_groups[region])
                             for region in regions])
        headers = ['ACTION', 'GROUP', 'REGION']
        actions = ['CREATE', 'DELETE']
        widths = [report.column_width(['ACTION'] + actions),
                  report.column_width(['GROUP'] + list(all_groups)),
                  report.column_width(['REGION'] + regions)]
        if args.headers:
            print ''.join([header.ljust(widths[index])
                           for index,header in enumerate(headers)])
        actions = [('CREATE', group, reg)
                   for reg in regions
                   for group in policy_groups[reg].difference(aws_groups[reg])]
        actions += [('DELETE', group, reg)
                    for reg in regions
                    for group in aws_groups[reg].difference(policy_groups[reg])]
        for action, group, region in actions:
            print '%s%s%s' % (action.ljust(widths[0]),
                              group.ljust(widths[1]),
                              region.ljust(widths[2]))
    if not args.groups_only:
        headers = ['ACTION', 'REGION', 'SOURCE',
                   'TARGET', 'PROTOCOL', 'PORT/TYPE']
        actions = ['ADD', 'REMOVE']
        policy_rules = [dict([('region', region)] + rule.items())
                        for rule in policy.parse(config)
                        for region in regions]
        aws_rules = aws.policy(config)
        widths = report.column_widths([[header] +
                                       [rule[header.lower()]
                                        for rule in policy_rules + aws_rules]
                                       for header in headers[1:]])
        widths = [report.column_width(['ACTION'] + actions)] + widths
        if args.headers:
            print ''.join([header.ljust(widths[index])
                           for index, header in enumerate(headers)])
        actions = [dict([('action', 'ADD')] + rule.items())
                   for rule in policy_rules if rule not in aws_rules]
        actions += [dict([('action', 'REMOVE')] + rule.items())
                    for rule in aws_rules if rule not in policy_rules]
        for act in sorted(actions, key=itemgetter('region')):
            print ''.join([report.format(act[hdr.lower()]).ljust(widths[index])
                           for index, hdr in enumerate(headers)])


def update(config, args):
    """
    Update groups/rules to match your configured policy. Adds new
    groups/rules, but does NOT remove groups/rules that are not defined in the
    configuration file.
    """
    regions = util.regions(config)
    account_id = aws.account_id(config)
    if not args.rules_only:
        policy_groups = dict([(region, set(policy.groups(config)))
                              for region in regions])
        aws_groups = dict([(region, set(aws.groups(region)))
                           for region in regions])
        for region in regions:
            conn = connect_to_region(region)
            for group in policy_groups[region].difference(aws_groups[region]):
                try:
                    conn.create_security_group(group, description='.')
                    action = 'CREATED'
                except (BotoClientError, BotoServerError), exc:
                    action = 'FAILED CREATING'
                    if args.debug:
                        print 'DEBUG: %s' % exc
                print '%s %s in %s' % (action, group, region)
    if not args.groups_only:
        policy_rules = [dict([('region', region)] + rule.items())
                        for rule in policy.parse(config)
                        for region in regions]
        aws_rules = aws.policy(config)
        update_rules = [rule for rule in policy_rules if rule not in aws_rules]
        for rule in update_rules:
            try:
                result = aws.authorize(rule, account_id)
                if result:
                    action = 'AUTHORIZED'
                else:
                    action = 'FAILED AUTHORIZING'
            except (BotoClientError, BotoServerError), exc:
                action = 'FAILED AUTHORIZING'
                if args.debug:
                    print 'DEBUG: %s' % exc
                template = '%s FROM: %s TO: %s PROTOCOL: %s PORT/TYPE: %s'
            print template % (action, rule['source'], rule['target'],
                              rule['protocol'], rule['port/type'])


def sync(config, args):
    """
    Synchronize groups/rules with your configured policy. Adds new
    groups/rules and REMOVES groups/rules not defined in the configuration
    file.
    """
    pass
