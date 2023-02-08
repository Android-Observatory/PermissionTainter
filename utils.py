#!/usr/bin/env python3

"""
Some small help methods that are used throughout the project.
"""

from intent import Intent, IntentFilter

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)

def _ns(name):
    """
    Add default Android XML namespace to string

    :param name: string to convert
    :returns: converted string
    """
    return NS_ANDROID + name


def is_class_external(class_obj):
    """
    Checks if a class is considered external or not.

    Androguard already defines a `is_external()' method that does that, however
    it does not consider newer support libraries. Here we extend the Androguard
    method to consider extra classes.

    :param class_obj: an Androguard ClassAnalysis object
    :return: boolean, tru if the class is external, false otherwise
    """
    return class_obj.is_external() or                                           \
           class_obj.name.startswith('Landroid/') or                            \
           class_obj.name.startswith('Landroidx/') or                           \
           class_obj.name.startswith('Lcom/google/android/material/') or        \
           class_obj.name.startswith('Lcom/google/android/gms/')


def get_fallback_return_value(return_type):
    """
    Get the default value for the supplied type. If `return_type' is not in the
    list of handle types, we return it without modification.

    :param return_type: the type of the return value
    :return: a fall back value of various type
    """
    # Nothing to return in that case
    if return_type == 'void' or return_type == 'V':
        return None

    # booleans - default to True
    if return_type == 'boolean' or return_type == 'Z':
        return True

    # We represent all those types as int, and default to 0
    if return_type in {'byte', 'short', 'char', 'integer', 'long',
                       'B', 'S', 'C', 'I', 'J'}:
        return 0

    # floats and doubles - return 0.0
    if return_type in {'float', 'double', 'F', 'D'}:
        return 0.0

    # Arrays or array-like types - return an empty list
    if '[]' in return_type or       \
            return_type in {'Ljava/util/List;',
                            'Ljava/lang/StringBuilder;',
                            'Ljava/util/Set;'}:
        return list()

    # String - return empty string
    if return_type == 'Ljava/lang/String;':
        return ''

    if return_type == 'Landroid/content/Intent;':
        return Intent()

    if return_type == 'Landroid/content/IntentFilter;':
        return IntentFilter()

    return return_type


def get_reg_value_or_fallback(registers, index, expected_type):
    """
    Get the value contain in a register, or a default value if it is not of the
    expected type.

    This function checks the type of the value contained in a register. If the
    value is not of the expected type, or if there is no value at all in the
    register, return a default value.

    :param registers: the registers of the program
    :param index: the index of the register to check
    :param expected_type: the type we want the register value to be, and the
                          type of the fallback value otherwise
    :return: the value of the register or a default value
    """
    # Easiest case: the value in the register is of the expected type
    if index in registers and isinstance(registers[index], expected_type):
        return registers[index]

    # Fallback mode: return a default value
    if expected_type == bool:
        return get_fallback_return_value('boolean')
    if expected_type == int:
        return get_fallback_return_value('int')
    if expected_type == float:
        return get_fallback_return_value('float')
    if expected_type == list:
        return get_fallback_return_value('Ljava/util/List;')
    if expected_type == str:
        return get_fallback_return_value('Ljava/lang/String;')
    if expected_type == Intent:
        return get_fallback_return_value('Landroid/content/Intent;')
    if expected_type == IntentFilter:
        return get_fallback_return_value('Landroid/content/IntentFilter;')
    return None
