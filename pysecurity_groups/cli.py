### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Command line interface for pysecurity-groups."""
import errno
import sys

from argparse import ArgumentParser

import policy as policy


def main():
    """
    Entry point for the pysecurity_groups CLI.
    """
    args = get_parser().parse_args()
    ### The reporting functions use print statements. If you pipe the output
    ### of this script to, for example, less, and quit before all the output
    ### is consumed, the print statements will raise an IOError indicating a
    ### broken pipe. We deal with that here.
    try:
        args.dispatch_fn(args)
    except IOError, exc:
        if exc.errno == errno.EPIPE:
            sys.exit(errno.EPIPE)
        else:
            raise exc
    except KeyboardInterrupt:
        print 'Interrupted'
        sys.exit(255)


def get_parser():
    """
    Return a parser for the command-line arguments.
    """
    ##############################################
    ### Top-level parser and global arguments. ###
    ##############################################
    parser = ArgumentParser(description="""Command-line utility for working
                            with EC2 security groups in bulk.""")
    parser.add_argument('-p', '--policy', help="""Path to the security-groups
                        policy file.  Default: %(default)s.""",
                        default='/etc/security-groups/security-groups.policy')
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
    # ### 'aws-policy' subcommand
    # aws_policy_parser = subparsers.add_parser('aws-policy', help="""Generate a
    #                                           report detailing your current
    #                                           groups/rules as reported by the
    #                                           AWS API.""")
    # aws_policy_parser.set_defaults(dispatch_fn=aws_policy)
    # ### 'diff' subcommand
    # diff_parser = subparsers.add_parser('diff', help="""Generate a report
    #                                     showing the differences between your
    #                                     desired groups/rules and your current
    #                                     groups/rules.""")
    # diff_parser.set_defaults(dispatch_fn=diff)
    # ### 'sync' subcommand
    # sync_parser = subparsers.add_parser('sync', help="""Synchronize
    #                                     groups/rules with your configured
    #                                     policy. Adds new groups/rules and
    #                                     REMOVES groups/rules not defined in
    #                                     the configuration file.""")
    # sync_parser.set_defaults(dispatch_fn=sync)
    # ### 'update' subcommand
    # update_parser = subparsers.add_parser('update', help="""Update
    #                                       groups/rules to match your
    #                                       configured policy. Adds new
    #                                       groups/rules, but does NOT remove
    #                                       groups/rules that are not defined in
    #                                       the configuration file.""")
    # update_parser.set_defaults(dispatch_fn=update)
    return parser


def policy_report(args):
    print policy.parse(args.policy)
