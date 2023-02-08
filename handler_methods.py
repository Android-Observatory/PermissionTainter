#!/usr/bin/env python3

"""
Handlers related methods
"""

import time
import pprint
from graph_methods import build_cfg_for_method
from igraph_trails import get_all_trails
from handler import Handler
from intent import Intent, IntentFilter
from fields import ClassField
from class_instance import ClassInstance
from utils import is_class_external, get_fallback_return_value, get_reg_value_or_fallback
from instruction import CALL_OPERATIONS, CallInstruction

def get_handlers(analysis_obj, fields, debug, timing):
    """
    Parse the DEX code and get Handlers objects and their targets

    :param analysis_obj: Androguard analysis object
    :param debug: boolean, print debug messages or not
    :param timing: boolean, print timing messages or not
    :return: dictionary of handlers and their targets

    TODO: we need to handle the post* family of methods too
    """

    post_methods = {"post", "postAtTime", "postDelayed"}
    send_methods = {"sendEmptyMessage", "sendMessage", "sendMessageAtTime", "sendMessageDelayed"}

    methods_to_analyze = set()
    for class_obj in analysis_obj.get_internal_classes():
        if is_class_external(class_obj):
            continue

        for method_obj in class_obj.get_methods():
            for xref_class, xref_method, _ in method_obj.get_xref_to():
                if xref_class.name == 'Landroid/os/Handler;' and              \
                        xref_method.name in post_methods:
                    if debug:
                        print("{}->{}".format(class_obj.name, method_obj.name))
                    methods_to_analyze.add((class_obj, method_obj))

    for class_obj in analysis_obj.get_internal_classes():
        if is_class_external(class_obj):
            continue

        for method_obj in class_obj.get_methods():
            for xref_class, xref_method, _ in method_obj.get_xref_to():
                if xref_class.name == 'Landroid/os/Handler;' and              \
                        xref_method.name in send_methods:
                    if debug:
                        print("{}->{}".format(class_obj.name, method_obj.name))
                    methods_to_analyze.add((class_obj, method_obj))

    handlers = dict()
    for class_obj, method_obj in methods_to_analyze:
        if timing:
            print('[get_handlers] getting CFG for {}->{}'.format(class_obj.name, method_obj.name))
        start_time = time.time()
        cfg = build_cfg_for_method(method_obj, debug)
        if timing:
            print('[get_handlers] got CFG for {}->{}, took {} seconds'.format(
                  class_obj.name,
                  method_obj.name,
                  round(time.time() - start_time, 2)))
        if class_obj.name not in handlers:
            handlers[class_obj.name] = dict()

        key = (method_obj.name, method_obj.descriptor)
        handlers[class_obj.name][key] = set()

        registers = dict()
        last_invoke_value = None

        # Get all return blocks
        return_blocks = [node for node in cfg.vs if
                         list(node['basic_block'].get_instructions())[-1].get_op_value() in {0x0e, 0x0f, 0x10, 0x11}]
        # Get all possible paths from the firs block to all return blocks
        # paths = nx.all_simple_paths(cfg, source=list(cfg.nodes)[0], target=return_blocks)
        root_node = cfg.vs.select(is_root_eq=True)[0]
        paths = list(get_all_trails(cfg, root_node, to=return_blocks))
        if timing:
            print('[get_handlers] got {} paths'.format(len(paths)))

        start_path = time.time()
        for path in paths:
            for node_idx in path:
                block = cfg.vs[node_idx]['basic_block']
                idx = block.start
                for inst in block.get_instructions():
                    op_value = inst.get_op_value()
                    operands = inst.get_operands()
                    length = inst.get_length()
                    disasm = inst.disasm()
                    idx += inst.get_length()

                    if debug:
                        print(idx, disasm)

                    # move*
                    # Note: does not include move-result*
                    if op_value in {0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09}:
                        dst_register = operands[0][1]
                        src_register = operands[1][1]

                        if src_register not in registers:
                            continue

                        registers[dst_register] = registers[src_register]
                        del registers[src_register]
                        continue

                    # move-result-*
                    if op_value in {0x0a, 0x0b, 0x0c}:
                        dst_register = operands[0][1]
                        if last_invoke_value is not None:
                            registers[dst_register] = last_invoke_value
                            last_invoke_value = None
                        continue

                    # const-* (except const-class)
                    if op_value in {0x12, 0x13, 0x14, 0x15, 0x16,
                                    0x17, 0x18, 0x19, 0x1a, 0x1b}:
                        dst_register = operands[0][1]
                        value = operands[1][-1]

                        registers[dst_register] = value
                        continue

                    # const-string and const-string/jumbo
                    if op_value in {0x1a, 0x1b}:
                        dst_register = operands[0][1]
                        const_str = operands[1][-1]
                        registers[dst_register] = const_str
                        continue

                    # const-class
                    if op_value == 0x1c:
                        dst_register = operands[0][1]
                        class_name = operands[1][-1]

                        # Conversion to regular package name style
                        class_name = class_name[1:-1].replace('/', '.')

                        registers[dst_register] = str(class_name)
                        continue

                    # array-length
                    if op_value == 0x21:
                        dst_register = operands[0][1]
                        array_register = operands[1][1]
                        if array_register not in registers or       \
                                not isinstance(registers[array_register], list):
                            registers[dst_register] = 0
                        else:
                            registers[dst_register] = len(registers[array_register])
                        continue

                    # new-instance
                    if op_value == 0x22:
                        dst_register = operands[0][1]
                        instance_class = operands[1][-1]
                        if instance_class == 'Landroid/content/Intent;':
                            new_intent = Intent()
                            registers[dst_register] = new_intent
                        elif instance_class == 'Ljava/lang/StringBuilder;':
                            registers[dst_register] = list()
                        elif instance_class == 'Landroid/content/IntentFilter;':
                            new_filter = IntentFilter()
                            registers[dst_register] = new_filter
                        else:
                            instance = ClassInstance(instance_class)
                            registers[dst_register] = instance
                        continue

                    # new-array
                    if op_value == 0x23:
                        dst_register = operands[0][1]
                        registers[dst_register] = list()
                        continue

                    # aget-*
                    if op_value in {0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a}:
                        dst_register = operands[0][1]
                        array_register = operands[1][1]
                        index_register = operands[2][1]

                        if array_register not in registers:
                            continue
                        array = registers[array_register]

                        if index_register not in registers or                     \
                                not isinstance(array, list) or                    \
                                not isinstance(index_register, int) or            \
                                not isinstance(registers[index_register], int) or \
                                registers[index_register] >= len(array):
                            continue
                        else:
                            registers[dst_register] = array[registers[index_register]]
                        continue

                    # aput-*
                    if op_value in {0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51}:
                        src_register = operands[0][1]
                        array_register = operands[1][1]
                        index_register = operands[2][1]

                        if src_register not in registers:
                            continue
                        src_object = registers[src_register]

                        if array_register not in registers:
                            continue
                        array = registers[array_register]

                        if index_register not in registers or                     \
                                not isinstance(array, list) or                    \
                                not isinstance(index_register, int) or            \
                                not isinstance(registers[index_register], int) or \
                                registers[index_register] >= len(array):
                            array.append(src_object)
                        else:
                            array[registers[index_register]] = src_object
                        continue

                    # iget-*
                    if op_value in {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58}:
                        dst_register = operands[0][1]
                        class_name = operands[-1][-1].split(';')[0] + ';'
                        field_name = operands[-1][-1].split('>')[1].split()[0]

                        if class_name in fields and field_name in fields[class_name]:
                            registers[dst_register] = fields[class_name][field_name]
                            continue

                        # No field, probably an external class
                        field_type = operands[-1][-1].split()[-1]

                        # boolean - return True
                        if field_type == 'Z':
                            registers[dst_register] = True
                            continue

                        # int and chars - return 0
                        if field_type in {'B', 'S', 'C', 'I', 'J'}:
                            registers[dst_register] = 0
                            continue

                        # floats and doubles - return 0.0
                        if field_type in {'F', 'D'}:
                            registers[dst_register] = 0.0
                            continue

                        if field_type.startswith('[') or       \
                                field_type in {'Ljava/util/List;',
                                            'Ljava/lang/StringBuilder;',
                                            'Ljava/util/Set;'}:
                            registers[dst_register] = list()
                            continue

                        if field_type == 'Ljava/lang/String;':
                            registers[dst_register] = ''
                            continue

                        if field_type == 'Landroid/content/Intent;':
                            registers[dst_register] = Intent()
                            continue

                        if field_type == 'Landroid/content/IntentFilter;':
                            registers[dst_register] = IntentFilter()
                            continue

                        registers[dst_register] = None
                        continue

                    # iput-*
                    if op_value in {0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}:
                        src_register = operands[0][1]
                        class_name = operands[-1][-1].split(';')[0] + ';'
                        field_name = operands[-1][-1].split('>')[1].split()[0]

                        if src_register not in registers:
                            continue

                        if class_name in fields and field_name in fields[class_name]:
                            fields[class_name][field_name] = registers[src_register]
                            continue

                    # sget-*
                    if op_value in {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66}:
                        dst_register = operands[0][1]
                        class_name = operands[-1][-1].split(';')[0] + ';'
                        field_name = operands[-1][-1].split('>')[1].split()[0]

                        if class_name in fields and field_name in fields[class_name]:
                            registers[dst_register] = fields[class_name][field_name]
                            continue

                        # No field, probably an external class
                        field_type = operands[-1][-1].split()[-1]

                        # boolean - return True
                        if field_type == 'Z':
                            registers[dst_register] = True
                            continue

                        # int and chars - return 0
                        if field_type in {'B', 'S', 'C', 'I', 'J'}:
                            registers[dst_register] = 0
                            continue

                        # floats and doubles - return 0.0
                        if field_type in {'F', 'D'}:
                            registers[dst_register] = 0.0
                            continue

                        if field_type.startswith('[') or       \
                                field_type in {'Ljava/util/List;',
                                            'Ljava/lang/StringBuilder;',
                                            'Ljava/util/Set;'}:
                            registers[dst_register] = list()
                            continue

                        if field_type == 'Ljava/lang/String;':
                            registers[dst_register] = ''
                            continue

                        if field_type == 'Landroid/content/Intent;':
                            registers[dst_register] = Intent()
                            continue

                        if field_type == 'Landroid/content/IntentFilter;':
                            registers[dst_register] = IntentFilter()
                            continue

                        registers[dst_register] = None
                        continue

                    # sput-*
                    if op_value in {0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d}:
                        src_register = operands[0][1]
                        class_name = operands[-1][-1].split(';')[0] + ';'
                        field_name = operands[-1][-1].split('>')[1].split()[0]

                        if src_register not in registers:
                            continue

                        if class_name in fields and field_name in fields[class_name]:
                            fields[class_name][field_name] = registers[src_register]
                            continue

                    if op_value in CALL_OPERATIONS:
                        instruction = CallInstruction(op_value, operands, disasm, length)

                        if instruction.get_kind() == 'VirtualCall':

                            if instruction.get_called_target() in {
                                    'Landroid/os/Handler;->sendEmptyMessage(I)Z',
                                    'Landroid/os/Handler;->sendEmptyMessageAtTime(I J)Z',
                                    'Landroid/os/Handler;->sendEmptyMessageDelayed(I J)Z',
                                    'Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z',
                                    'Landroid/os/Handler;->sendMessageAtFrontOfQueue(Landroid/os/Message;)Z',
                                    'Landroid/os/Handler;->sendMessageAtTime(Landroid/os/Message; J)Z',
                                    'Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message; J)Z'}:

                                handler_register = operands[0][1]
                                if handler_register not in registers:
                                    # TODO: handle error
                                    continue

                                # Most likely, the register will hold an
                                # instance field, or a handler object directly
                                # --- we check the type
                                if not isinstance(registers[handler_register], ClassField)         \
                                        and not isinstance(registers[handler_register], Handler):
                                    # TODO: handle error
                                    continue

                                if isinstance(registers[handler_register].fvalue, Handler):
                                    handler_class_name = registers[handler_register].fvalue.looper
                                else:
                                    handler_class_name = registers[handler_register].ftype

                                # We try to get the ClassAnalysis object
                                # This also serves as a check for external methods
                                handler_class_analysis = analysis_obj.get_class_analysis(handler_class_name)
                                if handler_class_analysis is None:
                                    continue

                                # We try to get the handleMessage method
                                # analysis object from that class
                                # There are two possible methods, depending on
                                # if the class implements the Handler.Callback
                                # interface or not
                                handle_message_method =             \
                                        analysis_obj.get_method_analysis_by_name(handler_class_name,
                                                                                 "handleMessage",
                                                                                 "(Landroid/os/Message;)V")
                                if handle_message_method is None:
                                    handle_message_method =             \
                                            analysis_obj.get_method_analysis_by_name(handler_class_name,
                                                                                     "handleMessage",
                                                                                     "(Landroid/os/Message;)Z")

                                # We also need the offset at which the
                                # invocation happens
                                where_used = idx - inst.get_length()

                                # We store the results in the handlers
                                # dictionary --- we'll add the xrefs from the
                                # main file (as we do for intents)
                                key = (method_obj.name, method_obj.descriptor)
                                handlers[class_obj.name][key].add((handler_class_analysis,
                                                                   handle_message_method,
                                                                   where_used))

                                continue

                            if instruction.get_called_target() == 'Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;':
                                builder_register = instruction.get_parameters()[0]
                                str_register = instruction.get_parameters()[1]

                                if builder_register not in registers:
                                    registers[builder_register] = list()

                                appended = get_reg_value_or_fallback(registers, str_register, str)
                                # In case we got the fallback value
                                registers[str_register] = appended

                                registers[builder_register].append(appended)
                                last_invoke_value = registers[builder_register]
                                continue

                            if instruction.get_called_target() == 'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;':
                                builder_register = instruction.get_parameters()[0]

                                builder = get_reg_value_or_fallback(registers, builder_register, list)

                                last_invoke_value = ''.join([str(item) for item in builder])
                                continue

                        if instruction.get_kind() == 'StaticCall':
                            if instruction.get_called_target() == 'Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;':
                                last_invoke_value = '/sdcard/'
                                continue

                            if instruction.get_called_target() == 'Ljava/io/File;->getPath()Ljava/lang/String;':
                                dst_register = instruction.get_parameters()[0]

                                if registers[dst_register] == '/sdcard/':
                                    # getPath() called after getExternalStorageDirectory()
                                    last_invoke_value = '/sdcard/'
                                else:
                                    last_invoke_value = 'GET_PATH'
                                continue

                            if instruction.get_called_target() == 'Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;':
                                # No need to parse, we just move the string to the right register
                                dst_register = instruction.get_parameters()[0]
                                last_invoke_value = get_reg_value_or_fallback(registers, dst_register, str)
                                continue

                            if instruction.get_called_target() == 'Ljava/lang/System;->currentTimeMillis()J':
                                last_invoke_value = 100 * int(time.time())
                                continue

                        if instruction.get_kind() == 'InterfaceCall':
                            if instruction.get_called_target() == 'Ljava/util/List;->size()I':
                                list_register = instruction.get_parameters()[0]
                                if list_register not in registers or        \
                                        not isinstance(registers[list_register], list):
                                    last_invoke_value = 0
                                else:
                                    last_invoke_value = len(registers[list_register])
                                continue


                        # We do type analysis of the return types of prototypes we
                        # do not otherwise consider, to avoid AttributeError
                        # exceptions later on, because the registers do not hold
                        # values of the required type
                        fallback_return_value = get_fallback_return_value(instruction.get_return_type())

                        if fallback_return_value is None:
                            continue

                        try:
                            dst_register = instruction.get_parameters()[0]
                        except IndexError:
                            # Sometimes there is a return type but no
                            # registers. Maybe a bug in Androguard?
                            continue

                        if dst_register in registers and                            \
                                isinstance(registers[dst_register], Intent):
                            # There is already an intent in the target
                            # register, which might be just because we do not
                            # support the function call. We ignore.
                            continue

                        if dst_register in registers and                            \
                                isinstance(registers[dst_register], IntentFilter):
                            # There is already an intent filter in the target
                            # register, which might be just because we do not
                            # support the function call. We ignore.
                            continue

                        # We try to get the prototype of the method that
                        # is called, and use that instead  (that could be
                        # helpful for later analysis)
                        if fallback_return_value == '':
                            fallback_return_value = instruction.get_called_target()

                        registers[dst_register] = fallback_return_value
                        last_invoke_value = fallback_return_value
                        continue

        if timing:
            print('[get_handlers]   end path, took {} seconds'.format(round(time.time() - start_path, 2)))

    return handlers
