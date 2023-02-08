#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Intent and intent filter classes.
These classes are use to represent intents in the taint analysis engine.

Intent flags were extracted from: https://developer.android.com/reference/android/content/Intent
"""

class Intent:
    """ Representation of an Intent """

    def __init__(self, pkg_name='', class_name='', action='', uri='', flags=0):
        self.target_pkg_name = pkg_name
        self.target_class_name = class_name
        self.action = action
        self.target_uri = uri
        self.flags = flags
        self.extras = set()
        self.component_type = None
        self.how_used = None
        self.where_used = None

    def __repr__(self):
        if self.component_type == 'activity':
            flags = ', '.join(self.flags_to_str(self.flags, 'activity'))
        elif self.component_type == 'receiver':
            flags = ', '.join(self.flags_to_str(self.flags, 'activity'))
        else:
            flags = ', '.join(self.flags_to_str(self.flags))

        intent = "Intent(target_pkg='{}', target_class='{}', action='{}', "     \
                 "uri='{}', flags='{}', type='{}', how_used='{}', "             \
                 "where_used='{}', extras='{}')".format(
            self.target_pkg_name,
            self.target_class_name,
            self.action,
            ''.join(self.target_uri),
            flags,
            self.component_type,
            self.how_used,
            self.where_used,
            ', '.join(['{}'.format(item[1]) for item in self.extras]))
        return intent

    def __eq__(self, other):
        if not isinstance(other, Intent):
            return NotImplemented

        return self.target_pkg_name == other.target_pkg_name and            \
                self.target_class_name == other.target_class_name and       \
                self.action == other.action and                             \
                self.target_uri == other.target_uri and                     \
                self.flags == other.flags and                               \
                self.extras == other.extras

    def __hash__(self):
        return hash(repr(self))

    @staticmethod
    def flags_to_str(flag, component_type=None):
        """ Print flags from integer value to string """

        converted_flag = list()

        for hex_value, str_value in COMMON_FLAGS.items():
            if flag & hex_value:
                converted_flag.append(str_value)

        if component_type == 'receiver':
            for hex_value, str_value in RECEIVER_FLAGS.items():
                if flag & hex_value:
                    converted_flag.append(str_value)
        elif component_type == 'activity':
            for hex_value, str_value in ACTIVITY_FLAGS.items():
                if flag & hex_value:
                    converted_flag.append(str_value)

        return converted_flag


class IntentFilter:
    """ Representation of a dynamically registered intent filter """
    def __init__(self, action=None, category=None, data_type=None):
        default_data_type = {
            'scheme': '',
            'host': '',
            'port': '',
            'path': '',
            'pathPattern': '',
            'pathPrefix': '',
            'mimeType': ''
        }

        if action is not None:
            self.action = action
        else:
            self.action = list()

        if action is not None:
            self.category = category
        else:
            self.category = list()

        self.data_type = data_type if data_type is not None else default_data_type

    def __repr__(self):
        # TODO: better representation of the data type
        intent_filter = "IntentFilter(action='{}', category='{}', data_type='{}')".format(
            self.action,
            self.category,
            self.data_type)

        return intent_filter

    def __eq__(self, other):
        if not isinstance(other, IntentFilter):
            return NotImplemented

        return self.action == other.action and          \
                self.category == other.category and     \
                self.data_type == other.data_type

    def __hash__(self):
        return hash(repr(self))


COMMON_FLAGS = {
        0x00000001: 'FLAG_GRANT_READ_URI_PERMISSION',
        0x00000002: 'FLAG_GRANT_WRITE_URI_PERMISSION',
        0x00000004: 'FLAG_FROM_BACKGROUND',
        0x00000008: 'FLAG_DEBUG_LOG_RESOLUTION',
        0x00000010: 'FLAG_EXCLUDE_STOPPED_PACKAGES',
        0x00000020: 'FLAG_INCLUDE_STOPPED_PACKAGES',
        0x00000040: 'FLAG_GRANT_PERSISTABLE_URI_PERMISSION',
        0x00000080: 'FLAG_GRANT_PREFIX_URI_PERMISSION',
        0x00000100: 'FLAG_DIRECT_BOOT_AUTO',
}

ACTIVITY_FLAGS = {
        0x00000200: 'FLAG_ACTIVITY_REQUIRE_DEFAULT',
        0x00000400: 'FLAG_ACTIVITY_REQUIRE_NON_BROWSER',
        0x00000800: 'FLAG_ACTIVITY_MATCH_EXTERNAL',
        0x00001000: 'FLAG_ACTIVITY_LAUNCH_ADJACENT',
        0x00002000: 'FLAG_ACTIVITY_RETAIN_IN_RECENTS',
        0x00004000: 'FLAG_ACTIVITY_TASK_ON_HOME',
        0x00008000: 'FLAG_ACTIVITY_CLEAR_TASK',
        0x00010000: 'FLAG_ACTIVITY_NO_ANIMATION',
        0x00020000: 'FLAG_ACTIVITY_REORDER_TO_FRONT',
        0x00040000: 'FLAG_ACTIVITY_NO_USER_ACTION',
        0x00080000: 'FLAG_ACTIVITY_NEW_DOCUMENT',
        0x00100000: 'FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY',
        0x00200000: 'FLAG_ACTIVITY_RESET_TASK_IF_NEEDED',
        0x00400000: 'FLAG_ACTIVITY_BROUGHT_TO_FRONT',
        0x00800000: 'FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS',
        0x01000000: 'FLAG_ACTIVITY_PREVIOUS_IS_TOP',
        0x02000000: 'FLAG_ACTIVITY_FORWARD_RESULT',
        0x04000000: 'FLAG_ACTIVITY_CLEAR_TOP',
        0x08000000: 'FLAG_ACTIVITY_MULTIPLE_TASK',
        0x10000000: 'FLAG_ACTIVITY_NEW_TASK',
        0x20000000: 'FLAG_ACTIVITY_SINGLE_TOP',
        0x40000000: 'FLAG_ACTIVITY_NO_HISTORY',
}

RECEIVER_FLAGS = {
        0x00200000: 'FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS',
        0x08000000: 'FLAG_RECEIVER_NO_ABORT',
        0x10000000: 'FLAG_RECEIVER_FOREGROUND',
        0x20000000: 'FLAG_RECEIVER_REPLACE_PENDING',
        0x40000000: 'FLAG_RECEIVER_REGISTERED_ONLY',
}
