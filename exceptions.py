#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom exceptions
"""

class NoSuchClassException(Exception):
    """
    The class could not be found in the app. Example:

    class_analysis_obj = analysis_obj.get_class_analysis(class_name)
    if class_analysis_obj is None:
        raise NoSuchClassException
    """
