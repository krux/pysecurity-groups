### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Command line interface for pysecurity-groups."""

import ConfigParser
import sys

from argparse import ArgumentParser

import pysecurity_groups.policy as policy


if __name__ == '__main__':
    sys.exit(main())


def main():
    """
    Entry point for the pysecurity_groups CLI.
    """
    args = get_parser().parse_args()
    config = get_config(args)

    args.dispatch_fn(config, args)


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
                                                  configuration file.
                                                  Default: %(default)s.""",
                        default='/etc/security-groups/security-groups.conf')
    parser.add_argument('-r', '--region', help="""Region to manage security
                                                  groups in. Can be specified
                                                  multiple times. Default:
                                                  us-east-1""", action='append')

    ##########################################
    ### Sub-command parsers and arguments. ###
    ##########################################
    subparsers = parser.add_subparsers(title='Sub-Commands',
                                       description='Valid sub-commands:')

    ### 'policy' subcommand
    policy_parser = subparsers.add_parser('policy', help="""Generate a report
                                          your desired configuration as parsed
                                          by this command.""")
    policy_parser.set_defaults(dispatch_fn=policy_report) ### dispatch to policy()

    ### 'report' subcommand
    report_parser = subparsers.add_parser('report', help="""Generate a report
                                          showing the differences between
                                          your desired configuration and your
                                          current security groups.""")
    report_parser.set_defaults(dispatch_fn=report) ### dispatch to report()

    ### 'sync' subcommand
    sync_parser = subparsers.add_parser('sync', help="""Synchronize security
                                        groups with your desired configuration.
                                        Adds new groups/rules and REMOVES
                                        groups/rules not defined in the
                                        configuration file.""")
    sync_parser.set_defaults(dispatch_fn=sync) ### dispatch to sync()

    ### 'update' subcommand
    update_parser = subparsers.add_parser('update', help="""Update security
                                          groups to match your desired
                                          configuration. Adds new groups/rules,
                                          but does NOT remove groups/rules that
                                          are not defined in the configuration
                                          file.""")
    update_parser.set_defaults(dispatch_fn=update) ### dispatch to update()

    return parser


def policy_report(config, args):
    """
    Output a report detailing the policy parsed from the configuration file.
    """
    policy_rules = policy.parse(config)
    from pprint import pprint
    pprint(policy_rules)


def report(config, args):
    """
    Output a report detailing the differences between the configured policy
    and the live rules as reported by the AWS API.
    """
    policy_regions = config.get('CONFIG', 'regions').split(',')
    policy_groups = policy.groups(config)


def sync(config, args):
    pass


def update(config, args):
    pass
