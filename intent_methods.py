#!/usr/bin/env python3

"""
Intent related methods
"""

import time

from intent import Intent, IntentFilter
from instruction import ARITHMETIC_INT_OPERATIONS, ARITHMETIC_INT_OPERATIONS_TOADDR,            \
                        ARITHMETIC_DOUBLE_OPERATIONS, ARITHMETIC_DOUBLE_OPERATIONS_TOADDR,      \
                        LOGICAL_OPERATIONS, SHIFT_UNARY_OPERATIONS,                             \
                        SHIFT_BINARY_OPERATIONS, UNARY_OPERATIONS,                              \
                        CAST_OPERATIONS, CALL_OPERATIONS
from instruction import CallInstruction, BinaryInstruction,                                     \
                        ShiftInstruction, UnaryInstruction
from graph_methods import build_cfg_for_method
from igraph_trails import get_all_trails
from utils import _ns, is_class_external, get_fallback_return_value, get_reg_value_or_fallback


def get_static_intent_filters(apk_obj):
    """
    Parses the manifest to get all statically declared intent filters

    Intent filters can be used in any components. We need them to know which
    component will received a broadcasted intent.

    Note: it is still possible to dynamically (un)register an intent filter. We
    ignore that for now, but we should think about whether it would be worth
    supporting, and at what performance cost as this imply parsing the whole DEX.

    :param apk_obj: APKAnalysis object from Androguard
    :return: dictionary of intent filters and list of classes declaring them
    """

    intent_filter_attrs = {
        'action': ['name'],
        'category': ['name'],
        'data': [
            'scheme',
            'host',
            'port',
            'path',
            'pathPattern',
            'pathPrefix',
            'mimeType'
        ]
    }

    intent_filters = {}

    # First get a dictionary of all intent filters
    for component in ['activity', 'activity-alias', 'service', 'receiver', 'provider']:
        for element in apk_obj.get_android_manifest_xml().findall('.//' + component):
            element_name = element.get(_ns('name'))
            if not element_name.startswith(apk_obj.get_package()):
                if element_name.startswith('.'):
                    element_name = apk_obj.get_package() + element_name
                else:
                    element_name = apk_obj.get_package() + '.' + element_name

            intent_filters[element_name] = list()

            for item in element.findall('.//intent-filter'):
                current_filter = dict()
                for key in intent_filter_attrs.keys():
                    current_filter[key] = list()

                for key, attributes in intent_filter_attrs.items():
                    for found_keys in item.findall(key):
                        if key == 'data':
                            values = {}
                            for attribute in attributes:
                                value = found_keys.get(_ns(attribute))
                                if value:
                                    values[attribute] = value

                            if values:
                                current_filter[key].append(values)
                        else:
                            for attribute in attributes:
                                value = found_keys.get(_ns(attribute))
                                if value not in current_filter[key]:
                                    current_filter[key].append(value)

                intent_filters[element_name].append(current_filter)

    # Also return another dict with actions and classes declaring the filter
    classes_declaring = dict()
    for declaring_class, filters in intent_filters.items():
        for intent_filter in filters:
            for action in intent_filter['action']:
                try:
                    classes_declaring[action].add(declaring_class)
                except KeyError:
                    classes_declaring[action] = {declaring_class}

    return intent_filters, classes_declaring


def get_icc_intents(analysis_obj, fields, debug, timing):
    """
    Parse the DEX code and get Inter Class Communication (ICC) intents

    :param analysis_obj: Androguard analysis object
    :param debug: boolean, print debug messages or not
    :param timing: boolean, print timing messages or not
    :return: dictionary of ICC intents
    """

    methods_to_analyze = set()
    for class_obj in analysis_obj.get_internal_classes():
        if is_class_external(class_obj):
            continue

        for method_obj in class_obj.get_methods():
            for xref_class, xref_method, _ in method_obj.get_xref_to():
                if xref_class.name == 'Landroid/content/Intent;' and          \
                        xref_method.name == '<init>':
                    methods_to_analyze.add((class_obj, method_obj))
                    continue

                if xref_class.name == 'Landroid/content/IntentFilter;' and    \
                        xref_method.name == '<init>':
                    methods_to_analyze.add((class_obj, method_obj))

    intents = dict()
    for class_obj, method_obj in methods_to_analyze:
        if timing:
            print('[get_icc_intents] getting CFG for {}->{}'.format(class_obj.name, method_obj.name))
        start_time = time.time()
        cfg = build_cfg_for_method(method_obj, debug)
        if timing:
            print('[get_icc_intents] got CFG for {}->{}, took {} seconds'.format(
                  class_obj.name,
                  method_obj.name,
                  round(time.time() - start_time, 2)))
        if class_obj.name not in intents:
            intents[class_obj.name] = dict()

        intents[class_obj.name][method_obj.name] = set()

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
            print('[get_icc_intents] got {} paths'.format(len(paths)))

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
                        continue

                    # new-array
                    if op_value == 0x23:
                        dst_register = operands[0][1]
                        registers[dst_register] = list()
                        continue

                    # cmpl-*
                    if op_value in {0x2d, 0x2f}:
                        dst_register = operands[0][1]
                        b_register = operands[1][1]
                        c_register = operands[2][1]

                        if b_register not in registers or                       \
                                not isinstance(registers[b_register], float):
                            registers[b_register] = 0.0
                        if c_register not in registers or                       \
                                not isinstance(registers[c_register], float):
                            registers[c_register] = 0.0

                        b = registers[b_register]
                        c = registers[c_register]
                        if b == c:
                            registers[dst_register] = 0
                        elif b > c:
                            registers[dst_register] = 1
                        elif b < c:
                            registers[dst_register] = -1

                        continue

                    # cmpg-*
                    if op_value in {0x2e, 0x30}:
                        dst_register = operands[0][1]
                        b_register = operands[1][1]
                        c_register = operands[2][1]

                        if b_register not in registers or                       \
                                not isinstance(registers[b_register], float):
                            registers[b_register] = 0.0
                        if c_register not in registers or                       \
                                not isinstance(registers[c_register], float):
                            registers[c_register] = 0.0

                        b = registers[b_register]
                        c = registers[c_register]
                        if b == c:
                            registers[dst_register] = 0
                        elif b > c:
                            registers[dst_register] = 1
                        elif b < c:
                            registers[dst_register] = -1

                        continue

                    # cmp-long
                    if op_value == 0x31:
                        dst_register = operands[0][1]
                        b_register = operands[1][1]
                        c_register = operands[2][1]

                        if b_register not in registers or                       \
                                not isinstance(registers[b_register], int):
                            registers[b_register] = 0.0
                        if c_register not in registers or                       \
                                not isinstance(registers[c_register], int):
                            registers[c_register] = 0.0

                        b = registers[b_register]
                        c = registers[c_register]
                        if b == c:
                            registers[dst_register] = 0
                        elif b > c:
                            registers[dst_register] = 1
                        elif b < c:
                            registers[dst_register] = -1

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

                        # TODO: maybe we should first check if there is an intent
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

                            if instruction.get_called_target() == 'Landroid/content/Intent;->setClassName(Ljava/lang/String; Ljava/lang/String;)Landroid/content/Intent;':
                                intent_register = instruction.get_parameters()[0]
                                pkg_name_register = instruction.get_parameters()[1]
                                class_name_register = instruction.get_parameters()[2]

                                pkg_name = get_reg_value_or_fallback(registers, pkg_name_register, str)
                                class_name = get_reg_value_or_fallback(registers, class_name_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent(pkg_name, class_name, '', '', 0)
                                    registers[intent_register] = new_intent
                                else:
                                    # TODO
                                    # pprint.pprint(registers)
                                    # print(intent_register)
                                    current_intent = registers[intent_register]
                                    current_intent.target_pkg_name = pkg_name
                                    current_intent.target_class_name = class_name

                                last_invoke_value = registers[intent_register]
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;->setClassName(Landroid/content/Context; Ljava/lang/String;)Landroid/content/Intent;':
                                intent_register = instruction.get_parameters()[0]
                                context_register = instruction.get_parameters()[1]
                                class_name_register = instruction.get_parameters()[2]

                                class_name = get_reg_value_or_fallback(registers, class_name_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent('', class_name, '', '', 0)
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.target_class_name = class_name

                                last_invoke_value = registers[intent_register]
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;->setClass(Landroid/content/Context; Ljava/lang/Class;)Landroid/content/Intent;':
                                intent_register = instruction.get_parameters()[0]
                                context_register = instruction.get_parameters()[1]
                                class_register = instruction.get_parameters()[2]

                                class_name = get_reg_value_or_fallback(registers, class_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent('', class_name, '', '', 0)
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.target_class_name = class_name

                                last_invoke_value = registers[intent_register]
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;':
                                intent_register = instruction.get_parameters()[0]
                                action_register = instruction.get_parameters()[1]

                                action = get_reg_value_or_fallback(registers, action_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent('', '', action, '', 0)
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.action = action

                                last_invoke_value = registers[intent_register]
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;':
                                intent_register = instruction.get_parameters()[0]
                                pkg_name_register = instruction.get_parameters()[1]

                                pkg_name = get_reg_value_or_fallback(registers, pkg_name_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent(pkg_name, '', '', '', 0)
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.target_pkg_name = pkg_name

                                last_invoke_value = registers[intent_register]
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

                            if instruction.get_called_target() == 'Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;':
                                intent_register = instruction.get_parameters()[0]
                                flag_register = instruction.get_parameters()[1]

                                flag = get_reg_value_or_fallback(registers, flag_register, int)

                                if intent_register not in registers or      \
                                        not isinstance(registers[intent_register], Intent):
                                    registers[intent_register] = Intent()

                                registers[intent_register].flags = flag
                                last_invoke_value = registers[intent_register]
                                continue

                            # TODO: missing intent filters related methods
                            # Landroid/content/IntentFilter;->addDataAuthority(Ljava/lang/String; Ljava/lang/String;)V
                            # Landroid/content/IntentFilter;->addDataPath(Ljava/lang/String; I)V
                            # Landroid/content/IntentFilter;->addDataScheme(Ljava/lang/String;)V
                            # Landroid/content/IntentFilter;->addDataSchemeSpecificPart(Ljava/lang/String; I)V
                            # Landroid/content/IntentFilter;->addDataType(Ljava/lang/String; I)V

                            if instruction.get_called_target() == 'Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V':
                                filter_register = instruction.get_parameters()[0]
                                action_register = instruction.get_parameters()[1]

                                if filter_register not in registers or      \
                                        not isinstance(registers[filter_register], IntentFilter):
                                    registers[filter_register] = IntentFilter()

                                action = get_reg_value_or_fallback(registers, action_register, str)

                                registers[filter_register].action.append(action)
                                continue

                            if instruction.get_called_target() == 'Landroid/content/IntentFilter;->addCategory(Ljava/lang/String;)V':
                                filter_register = instruction.get_parameters()[0]
                                category_register = instruction.get_parameters()[1]

                                if filter_register not in registers or      \
                                        not isinstance(registers[filter_register], IntentFilter):
                                    registers[filter_register] = IntentFilter()

                                category = get_reg_value_or_fallback(registers, category_register, str)

                                registers[filter_register].category.append(category)
                                continue

                            # Note: the following methods are from the
                            # context class, so the first register is the
                            # context, which we ignore for now.
                            # TODO: make this more efficient
                            # TODO: missing methods
                            # if prototype.endswith(';->startIntentSender(Landroid/content/IntentSender; Landroid/content/Intent; I I I)V'):
                            # if prototype.endswith(';->startIntentSender(Landroid/content/IntentSender; Landroid/content/Intent; I I I Landroid/os/Bundle;)V'):
                            # if prototype.endswith(';->unbindService(Landroid/content/ServiceConnection;)V'):
                            if instruction.get_called_target().endswith(';->startActivities([Landroid/content/Intent;)V'):
                                intent_array_register = instruction.get_parameters()[1]

                                if intent_array_register not in registers or \
                                        not isinstance(registers[intent_array_register], list):
                                    continue

                                for intent in registers[intent_array_register]:
                                    try:
                                        intent.component_type = 'activity'
                                        intent.how_used = 'startActivity'
                                        intent.where_used = idx - inst.get_length()
                                    except AttributeError:
                                        continue
                                continue

                            if instruction.get_called_target().endswith(';->startActivities([Landroid/content/Intent; Landroid/os/Bundle;)V'):
                                intent_array_register = instruction.get_parameters()[1]

                                if intent_array_register not in registers or \
                                        not isinstance(registers[intent_array_register], list):
                                    continue

                                for intent in registers[intent_array_register]:
                                    try:
                                        intent.component_type = 'activity'
                                        intent.how_used = 'startActivity_bundle'
                                        intent.where_used = idx - inst.get_length()
                                    except AttributeError:
                                        continue
                                continue

                            if instruction.get_called_target().endswith(';->startActivity(Landroid/content/Intent;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'activity'
                                registers[intent_register].how_used = 'startActivity'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->startActivity(Landroid/content/Intent; Landroid/os/Bundle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'activity'
                                registers[intent_register].how_used = 'startActivity_bundle'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->startService(Landroid/content/Intent;)Landroid/content/ComponentName;'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'startService'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = '{}/{}'.format(
                                        registers[intent_register].target_pkg_name,
                                        registers[intent_register].target_class_name)
                                continue

                            if instruction.get_called_target().endswith(';->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'startForegroundService'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = '{}/{}'.format(
                                        registers[intent_register].target_pkg_name,
                                        registers[intent_register].target_class_name)
                                continue

                            if instruction.get_called_target().endswith(';->bindIsolatedService(Landroid/content/Intent; I Ljava/lang/String; Ljava/util/concurrent/Executor; Landroid/content/ServiceConnection;)Z'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'bindIsolatedService'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = True
                                continue

                            if instruction.get_called_target().endswith(';->bindService(Landroid/content/Intent; I Ljava/util/concurrent/Executor; Landroid/content/ServiceConnection;)Z'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'bindService'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = True
                                continue

                            if instruction.get_called_target().endswith(';->bindService(Landroid/content/Intent; Landroid/content/ServiceConnection; I)Z'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'bindService'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = True
                                continue

                            if instruction.get_called_target().endswith(';->bindServiceAsUser(Landroid/content/Intent; Landroid/content/ServiceConnection; I Landroid/os/UserHandle;)Z'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'bindServiceAsUser'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = True
                                continue

                            if instruction.get_called_target().endswith(';->sendBroadcast(Landroid/content/Intent; Ljava/lang/String;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendBroadcast(Landroid/content/Intent;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendBroadcastAsUser'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Ljava/lang/String;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendBroadcastAsUser'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendBroadcastWithMultiplePermissions(Landroid/content/Intent; [Ljava/util/String;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendBroadcastWithMultiplePermissions'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendOrderedBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendOrderedBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendOrderedBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendOrderedBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendOrderedBroadcastAsUser'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendStickyBroadcast(Landroid/content/Intent;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendStickyBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendStickyBroadcast(Landroid/content/Intent; Landroid/os/Bundle)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendStickyBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendStickyBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendStickyBroadcastAsUser'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendStickyOrderedBroadcast(Landroid/content/Intent; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendStickyOrderedBroadcast'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->sendStickyOrderedBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].how_used = 'sendStickyOrderedBroadcastAsUser'
                                registers[intent_register].where_used = idx - inst.get_length()
                                continue

                            if instruction.get_called_target().endswith(';->stopService(Landroid/content/Intent;)Z'):
                                intent_register = instruction.get_parameters()[1]

                                if intent_register not in registers or  \
                                        not isinstance(registers[intent_register], Intent):
                                    continue

                                registers[intent_register].component_type = 'service'
                                registers[intent_register].how_used = 'stopService'
                                registers[intent_register].where_used = idx - inst.get_length()

                                last_invoke_value = True
                                continue

                        if instruction.get_kind() == 'DirectCall':
                            if instruction.get_called_target() in {
                                    'Ljava/lang/StringBuilder;-><init>()V',
                                    'Ljava/lang/StringBuilder;-><init>(I)V'}:
                                builder_register = instruction.get_parameters()[0]
                                registers[builder_register] = list()
                                continue

                            if instruction.get_called_target() in {
                                    'Ljava/lang/StringBuilder;-><init>(Ljava/lang/CharSequence;)V',
                                    'Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V'}:
                                builder_register = instruction.get_parameters()[0]
                                registers[builder_register] = list()

                                string_register = instruction.get_parameters()[1]
                                if string_register in registers and         \
                                        isinstance(registers[string_register], str):
                                    registers[builder_register].append(registers[string_register])
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;-><init>()V':
                                intent_register = instruction.get_parameters()[0]
                                new_intent = Intent('', '', '', '', 0)
                                registers[intent_register] = new_intent
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;-><init>(Landroid/content/Intent;)V':
                                copy_register = instruction.get_parameters()[0]
                                src_register = instruction.get_parameters()[1]

                                src_intent = get_reg_value_or_fallback(registers, src_register, Intent)

                                if copy_register not in registers:
                                    copy_intent = Intent(src_intent.target_pkg_name,
                                                         src_intent.target_class_name,
                                                         src_intent.action,
                                                         src_intent.target_uri,
                                                         src_intent.flags)
                                else:
                                    copy_intent = registers[copy_register]
                                    copy_intent.target_pkg_name = src_intent.target_pkg_name
                                    copy_intent.target_class_name = src_intent.target_class_name
                                    copy_intent.action = src_intent.action
                                    copy_intent.target_uri = src_intent.target_uri
                                    copy_intent.flags = src_intent.flags

                                registers[copy_register] = copy_intent
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;-><init>(Ljava/lang/String;)V':
                                intent_register = instruction.get_parameters()[0]
                                action_register = instruction.get_parameters()[1]

                                action = get_reg_value_or_fallback(registers, action_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent('', '', action, '')
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.action = action

                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;-><init>(Ljava/lang/String; Landroid/net/Uri;)V':
                                intent_register = instruction.get_parameters()[0]
                                action_register = instruction.get_parameters()[1]
                                uri_register = instruction.get_parameters()[2]

                                action = get_reg_value_or_fallback(registers, action_register, str)
                                uri = get_reg_value_or_fallback(registers, uri_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent('', '', action, uri)
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.action = action
                                    current_intent.target_uri = uri
                                continue

                            if instruction.get_called_target() == 'Landroid/content/Intent;-><init>(Landroid/content/Context; Ljava/lang/Class;)V':
                                intent_register = instruction.get_parameters()[0]
                                # NOTE: we ignore this for now but we
                                # should try to get the target package name
                                # from the context, if possible statically
                                context_register = instruction.get_parameters()[1]
                                class_register = instruction.get_parameters()[2]

                                class_name = get_reg_value_or_fallback(registers, class_register, str)

                                if intent_register not in registers:
                                    new_intent = Intent('', class_name, '', '')
                                    registers[intent_register] = new_intent
                                else:
                                    current_intent = registers[intent_register]
                                    current_intent.target_class_name = class_name
                                continue

                            # Intent filters
                            if instruction.get_called_target() == 'Landroid/content/IntentFilter;-><init>()V':
                                filter_register = instruction.get_parameters()[0]
                                new_filter = IntentFilter()
                                registers[filter_register] = new_filter
                                continue

                            if instruction.get_called_target() == 'Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V':
                                filter_register = instruction.get_parameters()[0]
                                action_register = instruction.get_parameters()[1]

                                action = get_reg_value_or_fallback(registers, action_register, str)

                                if filter_register not in registers:
                                    new_filter = IntentFilter(action=list(action))
                                    registers[filter_register] = new_filter
                                else:
                                    current_filter = registers[filter_register]
                                    current_filter.action = list(action)
                                continue

                            if instruction.get_called_target() == 'Landroid/content/IntentFilter;-><init>(Ljava/lang/String; Ljava/lang/String;)V':
                                filter_register = instruction.get_parameters()[0]
                                action_register = instruction.get_parameters()[1]
                                data_type_register = instruction.get_parameters()[2]

                                action = get_reg_value_or_fallback(registers, action_register, str)
                                data_type = get_reg_value_or_fallback(registers, data_type_register, str)

                                if filter_register not in registers:
                                    new_filter = IntentFilter(action=list(action), data_type=list(data_type))
                                    registers[filter_register] = new_filter
                                else:
                                    current_filter = registers[filter_register]
                                    current_filter.action = list(action)
                                    current_filter.data_type = list(data_type)
                                continue

                            if instruction.get_called_target() == 'Landroid/content/IntentFilter;-><init>(Landroid/content/IntentFilter;)V':
                                copy_register = instruction.get_parameters()[0]
                                src_register = instruction.get_parameters()[1]

                                src_filter = get_reg_value_or_fallback(registers, src_register, IntentFilter)

                                if copy_register not in registers:
                                    copy_filter = IntentFilter(src_filter.action,
                                                               src_filter.category,
                                                               src_filter.data_type)
                                else:
                                    copy_filter = registers[copy_register]
                                    copy_filter.action = src_filter.action
                                    copy_filter.category = src_filter.category
                                    copy_filter.data_type = src_filter.data_type

                                registers[copy_register] = copy_filter
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

                        registers[dst_register] = fallback_return_value
                        last_invoke_value = fallback_return_value
                        continue

                    # and-int/2addr and and-long/2addr
                    if op_value in {0xb5, 0xc0}:
                        dst_register = operands[0][1]
                        src_register = operands[1][1]

                        try:
                            result = int(registers[dst_register] & registers[src_register])
                        except (KeyError, TypeError):
                            # TODO: this should not happen
                            result = 0

                        registers[dst_register] = result
                        continue

                    # or-int/2addr and or-long/2addr
                    if op_value in {0xb6, 0xc1}:
                        dst_register = operands[0][1]
                        src_register = operands[1][1]

                        try:
                            result = int(registers[dst_register] | registers[src_register])
                        except (KeyError, TypeError):
                            # TODO: this should not happen
                            result = 0

                        registers[dst_register] = result
                        continue

                    # xor-int/2addr and xor-long/2addr
                    if op_value in {0xb7, 0xc2}:
                        dst_register = operands[0][1]
                        src_register = operands[1][1]

                        try:
                            result = int(registers[dst_register] % registers[src_register])
                        except (KeyError, TypeError):
                            # TODO: this should not happen
                            result = 0

                        registers[dst_register] = result
                        continue

                    # rsub-int and rsub-int/lit8
                    if op_value in {0xd1, 0xd9}:
                        dst_register = operands[0][1]
                        source_register = operands[1][1]
                        value = int(operands[2][-1])

                        try:
                            registers[dst_register] = value - int(registers[source_register])
                        except KeyError:
                            # TODO: this should not happen
                            registers[dst_register] = 0
                            continue
                        continue

                    # Depending on the op_value, the instruction type is different
                    found = False
                    if op_value in ARITHMETIC_INT_OPERATIONS or op_value in ARITHMETIC_INT_OPERATIONS_TOADDR:
                        instruction = BinaryInstruction(op_value, operands, disasm, "Aritmethical", "int")
                        found = True
                    elif op_value in ARITHMETIC_DOUBLE_OPERATIONS or op_value in ARITHMETIC_DOUBLE_OPERATIONS_TOADDR:
                        instruction = BinaryInstruction(op_value, operands, disasm, "Arithmetical", "float")
                        found = True
                    elif op_value in LOGICAL_OPERATIONS:
                        instruction = BinaryInstruction(op_value, operands, disasm, "Logical", "int")
                        found = True
                    elif op_value in SHIFT_UNARY_OPERATIONS:
                        instruction = ShiftInstruction(op_value, operands, disasm, "Unary")
                        found = True
                    elif op_value in SHIFT_BINARY_OPERATIONS:
                        instruction = ShiftInstruction(op_value, operands, disasm, "Binary")
                        found = True
                    elif op_value in UNARY_OPERATIONS:
                        instruction = UnaryInstruction(op_value, operands, disasm, "Unary")
                        found = True
                    elif op_value in CAST_OPERATIONS:
                        instruction = UnaryInstruction(op_value, operands, disasm, "Cast")
                        found = True
                    if found:
                        try:
                            # We need this ugly hack until we have one instruction for
                            # operation type. Then, there will just be one if-elif
                            found = False
                            registers[instruction.dst_register] = eval(instruction.get_full_instruction())
                        except (KeyError, ZeroDivisionError, ValueError, TypeError):
                            registers[instruction.dst_register] = 0

            for item in registers.values():
                if isinstance(item, Intent):
                    intents[class_obj.name][method_obj.name].add(item)
                elif isinstance(item, list):
                    for element in item:
                        if isinstance(element, Intent):
                            intents[class_obj.name][method_obj.name].add(element)
        if timing:
            print('[get_icc_intents]   end path, took {} seconds'.format(round(time.time() - start_path, 2)))

    return intents
