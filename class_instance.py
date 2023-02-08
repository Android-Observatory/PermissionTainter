#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Class instance object, to represent any class instance that is not already
covered by custom python classes (e.g., Handler, Intent, IntentFilter).
"""

class ClassInstance:
    """ Representation of a ClassInstance """

    def __init__(self, class_name):
        self.class_name = class_name

    def __repr__(self):
        return "ClassInstance(class_name='{}')".format(self.class_name)

    def __eq__(self, other):
        if not isinstance(other, ClassInstance):
            return NotImplemented

        return self.class_name == other.class_name
