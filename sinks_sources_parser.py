#-*- coding: utf-8 -*-

'''
File with the parser for the file of sinks and sources
from FlowDroid, we will use the format used in that project
but here should be the parsers for other formats if necessary.

User should use just the method: retrieve_sinks_and_sources(filepath: str)
and internally different parsers could be used.
'''

from collections import namedtuple

class SourceSink:
    def __init__(self, class_name, method_name, descriptor):
        self.class_name = class_name
        self.method_name = method_name
        self.descriptor = descriptor

    def __repr__(self):
        return "SourceSink(class_name='{}', method_name='{}', descriptor='{}')".format(
                self.class_name,
                self.method_name,
                self.descriptor)

    def __str__(self):
        return "{}->{}{}".format(self.class_name, self.method_name, self.descriptor)


def get_types_as_descriptor(types_str: str):
    '''
    Get the types as smali types given the strings.
    There must be a space after the ';' for non-basic types in
    arguments, unless said type is the last one.

    :parameter types_str: types as whole str.
    :return: str
    '''
    smali_types = ""
    types_str = types_str.replace('(', '').replace(')', '')


    for type_str in types_str.split(','):
        contains_array = type_str.count('[]')

        if contains_array > 0:
            type_str = type_str.replace('[]','').strip()
            smali_types += '['*contains_array

        if type_str == "":
            continue

        if type_str == 'boolean':
            smali_types += 'Z'
        elif type_str == 'byte':
            smali_types += 'B'
        elif type_str == 'char':
            smali_types += 'C'
        elif type_str == 'double':
            smali_types += 'D'
        elif type_str == 'float':
            smali_types += 'F'
        elif type_str == 'int':
            smali_types += 'I'
        elif type_str == 'long':
            smali_types += 'J'
        elif type_str == 'short':
            smali_types += 'S'
        elif type_str == 'void':
            smali_types += 'V'
        else:
            smali_types += 'L' + type_str.replace('.','/') + '; '

    if smali_types.endswith('; '):
        smali_types = smali_types[:-1]

    return smali_types

def get_types_as_list(types_str: str):
    """
    Get the smali types of a string as a list of
    types, we will parse it as a list of types.
    :parameter types_str: string with a list of types (it can be just one).
    :return: list
    """
    types_list = []
    types_str = types_str.replace('(', '').replace(')', '')

    len_types_str = len(types_str)

    is_object = False
    is_array = False
    nested_arrays = 0
    start_index = 0

    for i in range(len_types_str):

        if is_object:
            if types_str[i] == ';':
                is_object = False
                if not is_array:
                    types_list.append(str(types_str[start_index:i+1]))
                else:
                    types_list.append(
                        str(types_str[start_index:i+1]) + "[]" * nested_arrays)
                    is_array = False
                    nested_arrays = 0
            else:
                continue

        if types_str[i] == 'Z':
            if not is_array:
                types_list.append('boolean')
            else:
                types_list.append('boolean' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'B':
            if not is_array:
                types_list.append('byte')
            else:
                types_list.append('byte' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'C':
            if not is_array:
                types_list.append('char')
            else:
                types_list.append('char' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'D':
            if not is_array:
                types_list.append('double')
            else:
                types_list.append('double' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'F':
            if not is_array:
                types_list.append('float')
            else:
                types_list.append('float' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'I':
            if not is_array:
                types_list.append('integer')
            else:
                types_list.append('integer' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'J':
            if not is_array:
                types_list.append('long')
            else:
                types_list.append('long' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'S':
            if not is_array:
                types_list.append('short')
            else:
                types_list.append('short' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'V':
            if not is_array:
                types_list.append('void')
            else:
                types_list.append('void' + '[]'*nested_arrays)
                is_array = False
                nested_arrays = 0
        elif types_str[i] == 'L':
            is_object = True
            start_index = i
        elif types_str[i] == '[':
            is_array = True
            nested_arrays += 1

    return types_list

def flowdroid_sinks_and_sources_parser(filepath: str):
    '''
    Method to parse the flowdroid sources and sinks file

    :param filepath: path of the file to parse.
    :return: list[sinks], list[sources]
    '''
    sinks = []
    sources = []

    with open(filepath, 'r') as file_:
        i = 0
        for line in file_.readlines():
            i += 1
            line = line.strip()
            if line == '' or line[0] == '%': # nothing or a comment, move to next line
                continue
            if line[0] == '<':
                try:
                    tokens = line.split(' ')
                    if tokens[-1] not in {'_SINK_', '_SOURCE_', '_BOTH_'}:
                        print("Error reading line number %d: '%s'. Could not recognize last token: '%s'" % (i, line, tokens[-1]))
                        continue

                    class_name = 'L' + tokens[0].replace('<','').replace(':','').replace('.', '/').strip() + ';'
                    return_type = get_types_as_descriptor(tokens[1].strip())
                    method_name = tokens[2].split('(')[0].strip()
                    method_parameters = get_types_as_descriptor('(' + tokens[2].split('(')[1].replace('>','').strip())
                    descriptor = '(' + method_parameters + ')' + return_type

                    obj = SourceSink(class_name, method_name, descriptor)

                    if tokens[-1] == '_SINK_':
                        sinks.append(obj)
                    elif tokens[-1] == '_SOURCE_':
                        sources.append(obj)
                    elif tokens[-1] == '_BOTH_':
                        sinks.append(obj)
                        sources.append(obj)
                except Exception as exc:
                    print("Exception parsing line %d ('%s'): '%s'" % (i, line, str(exc)))
                    continue

    return sinks, sources

def retrieve_sinks_and_sources(filepath: str):
    '''
    Main method of file, this method will use internally different parsers
    if necessary to retrieve a list of sinks and a list of sources, for the
    moment we will support Flowdroid but other formats could be supported too.

    :param filepath: path of the file to parse.
    :return: list[sinks], list[sources]
    '''

    if filepath == "":
        return [],[]

    # for the moment we just support flowdroid
    return flowdroid_sinks_and_sources_parser(filepath)
