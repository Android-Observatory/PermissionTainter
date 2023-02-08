#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bound services analysis
"""

from graph_methods import build_cfg_for_method
from class_instance import ClassInstance
from instruction import DexLifter, AssignmentInstruction, FieldInstruction
from exceptions import NoSuchClassException


def get_binder_objects_from_onbind(method_obj):
    """
    Return class names for all possible binder objects
    returned by the supplied onBind() method

    The onBind() method has to return a binder object.
    However, only getting the object return in the last
    block is not enough, as there may be another return
    statement somewhere in the code.

    Here is an example of onBind() method with two
    difference binder objects returned in pseudo-bytecode:

    0000    if-eqz p0, @0x08
    0004    const-class v0, Lmy/package/MyBinder;
    0008    return-object v0
    000a    const-class v0, Lmy/package/MyOtherBinder;
    000e    return-object v0

    In this case, if the parameter `p0' is equal to zero,
    onBind() will return a MyBinder object. Otherwise, it
    will return a MyOtherBinder object;

    :param method_obj: a MethodAnalysis object for a onBind() method
    :return: set of class name representing binder objects
    """

    # Build CFG
    cfg = build_cfg_for_method(method_obj)

    # Get root and all return blocks, which we will need to compute the paths
    root = method_obj.get_basic_blocks()[0]
    return_blocks = set()
    for block in method_obj.get_basic_blocks():
        if block.get_last().get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
            # Block is an end block
            return_blocks.add(block)

    # Get all paths from the root to all return blocks
    root_node = cfg.vs.select(basic_block_eq=root)[0]
    return_nodes = [cfg.vs.select(basic_block_eq=block)[0] for block in return_blocks]
    paths = list(cfg.get_all_simple_paths(root_node, to=return_nodes))

    # Set of binder objects to be returned
    binder_objects = set()

    # Lift instructions along all paths
    for path in paths:
        blocks_in_order = list()
        for block_id in path:
            block = cfg.vs[block_id]['basic_block']
            blocks_in_order.append(block)

        dex_lifter = DexLifter()
        lifted_instructions = dex_lifter.lift_method_blocks(blocks_in_order)

        # We only care about `const-class' and `iget' here
        registers = dict()
        last_index = 0

        for idx, instruction in lifted_instructions.items():
            last_index = idx

            if isinstance(instruction, AssignmentInstruction):
                if instruction.kind == 'ClassAssignment':
                    registers[instruction.get_dst_register()] =         \
                            (instruction.get_src_class(), 'const-class')
                if instruction.kind == 'ResultAssignment':
                    if instruction.get_src_register() not in registers:
                        if instruction.get_dst_register() in registers:
                            del registers[instruction.get_dst_register()]
                    else:
                        registers[instruction.get_dst_register()] =     \
                                registers[instruction.get_src_register()]
                        del registers[instruction.get_src_register()]
                continue

            if isinstance(instruction, FieldInstruction):
                field_proto = '{}->{} {}'.format(instruction.field_class,
                                                 instruction.field_name,
                                                 instruction.field_type)
                registers[instruction.get_src_or_dst_register()] =      \
                            (field_proto, 'iget')

        try:
            binder_objects.add(registers[lifted_instructions[last_index].get_return_register()])
        except KeyError:
            continue

    return binder_objects


def get_public_methods_from_class(class_analysis_obj):
    """
    Goes through the list of methods defined in the class to return public ones

    :param class_analysis_obj: Android ClassAnalysis object
    :return: set of MethodAnalysis methods
    """

    public_methods = set()
    for method_obj in class_analysis_obj.get_methods():
        if 'public' in str(method_obj.get_access_flags_string()):
            public_methods.add(method_obj)

    return public_methods


def get_available_methods_from_bound_service(analysis_obj, binder_class_name):
    """
    Goes through the list of methods defined by the binder class
    and return public ones

    :param analysis_obj: Androguard Analysis object
    :param binder_class_name: fully qualified class name (string)
    :return: set of public methods defined by the binder class
    """

    class_analysis_obj = analysis_obj.get_class_analysis(binder_class_name)

    if class_analysis_obj is None:
        raise NoSuchClassException

    return get_public_methods_from_class(class_analysis_obj)


def get_binder_methods_from_app(apk_obj, analysis_obj, fields):
    """
    Return the list of method analysis object for public methods defined
    by all binder objects returned from all the `onBind()' methods
    defined by services in the app.

    :param apk_obj: Androguard ApkAnalysis object
    :param analysis_obj: Androguard Analysis object
    :param fields: dictionary of fields for all the classes of the app
    :return: set of class names
    """

    binder_classes = set()
    for service in apk_obj.get_services():
        service_name = 'L{};'.format(service.replace('.', '/'))
        service_class_analysis = analysis_obj.get_class_analysis(service_name)

        if service_class_analysis is None:
            continue

        for method in service_class_analysis.get_methods():
            method_proto = '{}{}'.format(method.name,
                                         method.descriptor)
            if method_proto == 'onBind(Landroid/content/Intent;)Landroid/os/IBinder;':
                binders = get_binder_objects_from_onbind(method)
                for binder, operation in binders:
                    if operation == 'iget':
                        class_name, field_name = binder.split()[0].split('->')
                        if class_name not in fields or field_name not in fields[class_name]:
                            continue

                        binder_field = fields[class_name][field_name].fvalue
                        if isinstance(binder_field, ClassInstance):
                            binder_classes.add(str(binder_field.class_name))
                        elif isinstance(binder_field, str):
                            binder_classes.add(binder_field)

    binder_methods = set()
    for binder_class in binder_classes:
        try:
            binder_methods.update(get_available_methods_from_bound_service(analysis_obj,
                                                                           binder_class))
        except NoSuchClassException:
            continue

    return binder_methods


def taint_analyze_binder_methods(apk_obj, analysis_obj, fields, taint_engine):
    """
    Run taint analysis on the methods available through a binder object

    :param apk_obj: Androguard ApkAnalysis object
    :param analysis_obj: Androguard Analysis object
    :param fields: dictionary of fields for all the classes of the app
    :param taint_engine: TaintEngine object
    :return: dictionary of leaks (possibly empty)
    """

    # Get all binder methods (set of MethodAnalysis objects)
    binder_methods = get_binder_methods_from_app(apk_obj,
                                                 analysis_obj,
                                                 fields)

    leaks_per_method = dict()
    for method_obj in binder_methods:
        leaks = set()

        # Build CFG for method
        cfg = build_cfg_for_method(method_obj)

        # Get root and all return blocks, which we will need to compute the paths
        root = method_obj.get_basic_blocks()[0]
        return_blocks = set()
        for block in method_obj.get_basic_blocks():
            if block.get_last().get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                # Block is an end block
                return_blocks.add(block)

        # Get all paths from the root to all return blocks
        root_node = cfg.vs.select(basic_block_eq=root)[0]
        return_nodes = [cfg.vs.select(basic_block_eq=block)[0] for block in return_blocks]
        paths = list(cfg.get_all_simple_paths(root_node, to=return_nodes))

        # Set of binder objects to be returned
        binder_objects = set()

        # Lift instructions along all paths
        for path in paths:
            blocks_in_order = list()
            for block_id in path:
                block = cfg.vs[block_id]['basic_block']
                blocks_in_order.append(block)

            dex_lifter = DexLifter()
            lifted_instructions = dex_lifter.lift_method_blocks(blocks_in_order)

            # Run taint analysis and save leaks
            leaks.update(taint_engine.apply_taint_block(lifted_instructions,
                                                        method_obj,
                                                        False,      # debug
                                                        None))      # next_method_proto

        leaks_per_method[method_obj.full_name] = leaks

    return leaks_per_method
