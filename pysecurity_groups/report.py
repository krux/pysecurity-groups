### -*- coding: utf-8 -*-
###
### © 2012 Krux Digital, Inc.
### Author: Paul Lathrop <paul@krux.com>
###

"""Report formatting functions for pysecurity-groups."""

def column_width(data, padding=2):
    """
    Given a list of DATA items, return the length of the longest item +
    PADDING.
    """
    return max([len(str(item)) + padding for item in data])


def column_widths(data, padding=2):
    """
    Given a list of DATA items, each of which is itself a list, return a list
    of lengths of the longest item in each source list + PADDING.
    """
    return [column_width(src_list, padding) for src_list in data]


def format(data):
    """
    Given an item of DATA, format it for reporting.
    """
    if type(data) is tuple:
        return '%s-%s' % data
    return str(data)
