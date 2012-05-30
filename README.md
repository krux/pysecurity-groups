pysecurity_groups
=================
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
