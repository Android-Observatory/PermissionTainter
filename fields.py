#!/usr/bin/env python3

"""
Fields related methods
"""

from intent import Intent, IntentFilter
from handler import Handler
from class_instance import ClassInstance
from utils import is_class_external, get_fallback_return_value
from instruction import CALL_OPERATIONS, CallInstruction

class ClassField:
    def __init__(self, fname="", ftype=None, fvalue=None):
        self.fname = fname
        self.ftype = ftype
        if isinstance(fvalue, ClassField):
            self.fvalue = fvalue.fvalue
        else:
            self.fvalue = fvalue

    def __repr__(self):
        return "ClassField(fname='{}', ftype='{}', fvalue='{}')".format(self.fname,
                                                                        self.ftype,
                                                                        self.fvalue)


def load_fields_per_class(analysis):
    """
    Load names and initial values of class fields

    :param analysis: Androguard analysis object
    :return: a dictionary with fields names and initial values
    """

    fields = dict()

    for class_obj in analysis.get_internal_classes():
        if is_class_external(class_obj):
            continue

        for field_item in class_obj.get_fields():
            androguard_field_obj = field_item.get_field()

            class_name = androguard_field_obj.class_name
            if class_name not in fields:
                fields[class_name] = dict()

            init_value = androguard_field_obj.get_init_value()
            if init_value is not None:
                init_value = init_value.raw_value

            value_type = field_item.get_field().get_descriptor().decode()

            field_obj = ClassField()
            field_obj.fname = field_item.name
            field_obj.ftype = value_type
            field_obj.fvalue = init_value

            if field_obj.ftype is not None:
                if field_obj.ftype.startswith('['):
                    field_obj.fvalue = list()
                fields[class_name][field_obj.fname] = field_obj
                continue

            # boolean - return True
            if value_type == 'Z':
                field_obj.ftype = bool
                field_obj.fvalue = True
                fields[class_name][field_obj.fname] = field_obj
                continue

            # int and chars - return 0
            if value_type in {'B', 'S', 'C', 'I', 'J'}:
                field_obj.ftype = int
                field_obj.fvalue = 0
                fields[class_name][field_obj.fname] = field_obj
                continue

            # floats and doubles - return 0.0
            if value_type in {'F', 'D'}:
                field_obj.ftype = float
                field_obj.fvalue = 0.0
                fields[class_name][field_obj.fname] = field_obj
                continue

            if value_type.startswith('[') or       \
                    value_type in {'Ljava/util/List;',
                                   'Ljava/lang/StringBuilder;',
                                   'Ljava/util/Set;'}:
                field_obj.ftype = list
                field_obj.fvalue = list()
                fields[class_name][field_obj.fname] = field_obj
                continue

            if value_type == 'Ljava/lang/String;':
                field_obj.ftype = str
                field_obj.fvalue = ""
                fields[class_name][field_obj.fname] = field_obj
                continue

            if value_type == 'Landroid/content/Intent;':
                field_obj.ftype = Intent
                field_obj.fvalue = Intent()
                fields[class_name][field_obj.fname] = field_obj
                continue

            if value_type == 'Landroid/content/IntentFilter;':
                field_obj.ftype = IntentFilter
                field_obj.fvalue = IntentFilter()
                fields[class_name][field_obj.fname] = field_obj
                continue

            class_analysis = analysis.get_class_analysis(class_name)
            if value_type == 'Landroid/os/Handler;' or                  \
                    class_analysis.extends == 'Landroid/os/Handler;':
                field_obj.ftype = Handler
                field_obj.fvalue = Handler()
                fields[class_name][field_obj.fname] = field_obj
                continue

            # If we reach this point it means the current field is not a basic
            # type -- i.e., an object. We just store its fully qualified class
            # name in the `fields' dictionary.
            fields[class_name][field_obj.fname] = field_obj

        # TODO: clean this up
        for method in class_obj.get_methods():
            if method.name == '<clinit>' or method.name == '<init>':
                registers = dict()
                last_invoke_value = None
                for block in method.get_basic_blocks():
                    for inst in block.get_instructions():
                        op_value = inst.get_op_value()
                        operands = inst.get_operands()

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

                        # new-instance
                        if op_value == 0x22:
                            dst_register = operands[0][1]
                            class_name = operands[1][-1]
                            instance = ClassInstance(class_name)
                            registers[dst_register] = instance

                        # new-array
                        if op_value == 0x23:
                            dst_register = operands[0][1]
                            registers[dst_register] = list()
                            continue

                        # new-filled-array and new-filled-array/range
                        if op_value in {0x24, 0x25}:
                            array = list()

                            for operand in operands[:-1]:
                                register = operand[1]
                                if register not in registers:
                                    continue
                                try:
                                    array.append(str(registers[register]))
                                except TypeError:
                                    continue

                            last_invoke_value = array

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

                            if isinstance(registers[array_register], ClassField):
                                array = registers[array_register].fvalue
                            else:
                                array = registers[array_register]

                            is_class_field_object = False
                            if isinstance(array, ClassField):
                                field_obj = array
                                array = field_obj.fvalue
                                is_class_field_object = True

                            if not isinstance(array, list):
                                array = [src_object]
                            elif index_register not in registers or                     \
                                    not isinstance(index_register, int) or            \
                                    not isinstance(registers[index_register], int) or \
                                    registers[index_register] >= len(array):
                                array.append(src_object)
                            else:
                                array[registers[index_register]] = src_object

                            if is_class_field_object:
                                field_obj.fvalue = array
                                registers[array_register] = field_obj

                            continue

                        # sget-*
                        if op_value in {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66} or \
                                op_value in {0x52, 0x53, 0x54, 0x55, 0x56, 0x58}:
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
                        if op_value in {0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d} or \
                                op_value in {0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f}:
                            src_register = operands[0][1]
                            class_name = operands[-1][-1].split(';')[0] + ';'
                            field_name = operands[-1][-1].split('>')[1].split()[0]

                            if src_register not in registers:
                                continue

                            if class_name in fields and field_name in fields[class_name]:
                                fields[class_name][field_name].fvalue = registers[src_register]
                                continue

                        if op_value in CALL_OPERATIONS:
                            instruction = CallInstruction(op_value,
                                                          operands,
                                                          inst.disasm(),
                                                          inst.get_length())

                            return_reg = instruction.get_return_reg()

                            if instruction.get_kind() == 'DirectCall':
                                if instruction.get_called_target() == "Landroid/os/Handler;-><init>()V":
                                    handler_reg = instruction.get_parameters()[0]

                                    looper = class_obj.name
                                    callback = class_obj.name

                                    handler = Handler(looper=looper,
                                                      callback=callback)
                                    registers[handler_reg] = handler

                                elif instruction.get_called_target() == "Landroid/os/Handler;-><init>(Landroid/os/Handler$Callback;)V":
                                    handler_reg, callback_reg = instruction.get_parameters()

                                    # TODO: fix fallback values
                                    if callback_reg not in registers:
                                        callback = "BAR"
                                    else:
                                        if isinstance(registers[callback_reg], ClassInstance):
                                            callback = registers[callback_reg].class_name
                                        elif isinstance(registers[callback_reg], ClassField):
                                            callback = registers[callback_reg].ftype
                                        else:
                                            callback = "BAR2"

                                    looper = class_obj.name
                                    handler = Handler(looper=looper,
                                                      callback=callback)
                                    registers[handler_reg] = handler

                                elif instruction.get_called_target() == "Landroid/os/Handler;-><init>(Landroid/os/Looper;)V":
                                    handler_reg, looper_reg = instruction.get_parameters()

                                    # TODO: fix fallback values
                                    if looper_reg not in registers:
                                        looper = "FOO"
                                    else:
                                        if isinstance(registers[looper_reg], ClassInstance):
                                            looper = registers[looper_reg].class_name
                                        elif isinstance(registers[looper_reg], ClassField):
                                            looper = registers[looper_reg].ftype
                                        else:
                                            looper = "FOO2"

                                    callback = class_obj.name
                                    handler = Handler(looper=looper,
                                                      callback=callback)
                                    registers[handler_reg] = handler

                                elif instruction.get_called_target() == "Landroid/os/Handler;-><init>(Landroid/os/Looper; Landroid/os/Handler$Callback;)V":
                                    handler_reg, looper_reg, callback_reg = instruction.get_parameters()

                                    # TODO: fix fallback values
                                    if looper_reg not in registers:
                                        looper = "FOO"
                                    else:
                                        if isinstance(registers[looper_reg], ClassInstance):
                                            looper = registers[looper_reg].class_name
                                        elif isinstance(registers[looper_reg], ClassField):
                                            looper = registers[looper_reg].ftype
                                        else:
                                            looper = "FOO2"

                                    # TODO: fix fallback values
                                    if callback_reg not in registers:
                                        callback = "BAR"
                                    else:
                                        if isinstance(registers[callback_reg], ClassInstance):
                                            callback = registers[callback_reg].class_name
                                        elif isinstance(registers[callback_reg], ClassField):
                                            callback = registers[callback_reg].ftype
                                        else:
                                            callback = "BAR2"

                                    handler = Handler(looper=looper,
                                                      callback=callback)
                                    registers[handler_reg] = handler

                            elif instruction.get_kind() == 'VirtualCall':
                                if instruction.get_called_target() == 'Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;':
                                    if return_reg in registers and isinstance(registers[return_reg], ClassField):
                                        registers[return_reg] = registers[return_reg].fvalue

    return fields
