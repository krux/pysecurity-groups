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
    config = get_config(args.config)
    args.dispatch_fn(config, args)


def get_config(config_file):
    """
    Parse the configuration file and return a ConfigParser object.
    """
    config = ConfigParser.SafeConfigParser()
    config.read(config_file)
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


def report(config, args):
    """
    Output a report detailing the differences between the configured policy
    and the live rules as reported by the AWS API.
    """
    ### Get the regions. After that, we're done with the config section;
    ### remove it so we don't have to special-case it in the policy parsing
    ### code.
    if args.region is None:
        ### No regions were specified on the command line, so try loading them
        ### from the config file.
        try:
            policy_regions = config.get('CONFIG', 'regions').split(',')
        except ConfigParser.NoOptionError:
            ### No regions on the command line, and none in the config file,
            ### so use a sane default.
            policy_regions = ['us-east-1']
    else:
        policy_regions = args.region
    config.remove_section('CONFIG')

    ### Get the groups/rules defined by the policy.
    policy_groups = policy.groups(config)
    policy_rules = policy.parse(config)


def sync(config, args):
    pass


def update(config, args):
    pass
