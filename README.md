pysecurity_groups
=================
pysecurity-groups is a tool for managing EC2 security groups and
associated access rules in bulk. It provides commands for auditing as
well as updating your groups/rules. There is a single command-line
utility `security-groups` which is controlled by a configuration file
(see Configuration for details.)
```
usage: security-groups [-h] [-c CONFIG] [-r REGION] [--no-headers]
                       [--groups-only | --rules-only]
                       {policy,diff,aws-policy,sync,update} ...

Command-line utility for working with EC2 security groups in bulk.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the security-groups configuration file.
                        Default: /etc/security-groups/security-groups.conf.
  -r REGION, --region REGION
                        Region to manage security groups in. Can be specified
                        multiple times. Default: us-east-1
  --no-headers          Don't output header lines.
  --groups-only         Only report/operate on security groups, not rules.
  --rules-only          Only report/operate on security rules, not groups.
                        NOTE: This can lead to errors if your groups are not
                        already correctly defined in AWS.

Sub-Commands:
  Valid sub-commands:

  {policy,diff,aws-policy,sync,update}
    policy              Generate a report detailing your desired groups/rules
                        as parsed by this command.
    aws-policy          Generate a report detailing your current groups/rules
                        as reported by the AWS API.
    diff                Generate a report showing the differences between your
                        desired groups/rules and your current groups/rules.
    sync                Synchronize groups/rules with your configured policy.
                        Adds new groups/rules and REMOVES groups/rules not
                        defined in the configuration file.
    update              Update groups/rules to match your configured policy.
                        Adds new groups/rules, but does NOT remove
                        groups/rules that are not defined in the configuration
                        file.
```

Configuration
=============
By default, the `security-groups` command looks for a configuration
file in `/etc/security-groups/security-groups.conf`. This can be
over-ridden with the `-c` or `--config` command-line options.

The configuration file has an ini-like format with each "heading"
being a security group to manage; there are three "special" headings,
`CONFIG`, `VARIABLES`, and `GLOBAL`:

- The `CONFIG` section is for global configuration variables that
  control the operation of the security-groups script. Options
  specified in the configuration file are over-ridden by command-line
  options. Configuration options are:
  - `regions`: A comma-separated list of regions to manage security
    groups/rules in.

- The `VARIABLES` section defines variables which can be used in the
  security group sections for clarity or to save typing. A variable is
  defined as `name = value` - for example:

      [VARIABLES]
      any-ip = 0.0.0.0/0

  Variables are referred to using `@name`:

      [default]
      @any-ip: tcp:22

  Variables are expanded by text substitution, so anything that is
  valid where you use a variable reference is a valid value for the
  variable. Variables can **not** refer to other variables,
  however. This is invalid:

      [VARIABLES]
      puppet-master-east = 10.0.0.1
      puppet-master-west = 10.0.0.2
      puppet-masters = @puppet-master-east, @puppet-master-west

- Rules defined in the `GLOBAL` section are applied to *all* security
  groups.
