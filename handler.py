#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Handler class, used to representer a Handler object

Source: https://developer.android.com/reference/android/os/Handler
"""

class Handler:
    """ Representation of a Handler """

    def __init__(self, class_name="", looper="", callback=""):
        self.class_name = class_name
        self.looper = looper                # Looper class name
        self.callback = callback            # Callback class name

    def __repr__(self):
        return "Handler(class_name='{}', "                          \
               "looper_class_name='{}', "                           \
               "callback_class_name='{}'".format(                   \
               self.class_name, self.looper, self.callback)

    def __eq__(self, other):
        if not isinstance(other, Handler):
            return NotImplemented

        return self.class_name == other.class_name and              \
                self.looper == other.looper and                     \
                self.callback == other.callback
