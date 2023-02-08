#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Code of TaintEngine to apply tainting to smali registers
as well as defining the rules from taint propagation, we
will base our rules in those defined by taintdroid from
a static perspective, and what we will do is to apply
the semantics from different categories of instructions.
'''

import sys
import json

from androguard.misc import AnalyzeAPK, AnalyzeDex
from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodAnalysis, ExternalMethod
from instruction import *
from intent import Intent, IntentFilter
from sinks_sources_parser import SourceSink


class Leak:
    '''
    Representation of a Leak. This means that in this
    method from this class, a register from a source
    reached a sink
    '''

    def __init__(self, source, sink, sink_classname, sink_method, sink_offset):
        self.source = source
        self.sink = sink
        self.source_classname = ''
        self.source_method = ''
        self.sink_classname = sink_classname
        self.sink_method = sink_method
        self.sink_offset = sink_offset
        self.path = list()


    def __repr__(self):
        return "Leak(source={}, sink={}, source_class={}, source_method={}, sink_class={}, sink_method={}, sink_offset={}, path={})".format(
            self.source, self.sink, self.source_classname, self.source_method, self.sink_classname, self.sink_method, self.sink_offset, self.path)

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.source == other.source
                and self.sink == other.sink
                and self.source_classname == other.source_classname
                and self.source_method == other.source_method
                and self.sink_classname == other.sink_classname
                and self.sink_method == other.sink_method
                and self.sink_offset == other.sink_offset
                and self.path == other.path)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(str(self))

    def to_dict(self):
        return {'source': self.source,
                'sink': self.sink,
                'source_classname': self.source_classname,
                'source_method': self.source_method,
                'sink_classname': self.sink_classname,
                'sink_method': self.sink_method,
                'sink_offset': self.sink_offset,
                'path': self.path}

    def toJSON(self):
        return json.dumps({'source': self.source,
                           'sink': self.sink,
                           'source_classname': self.source_classname,
                           'source_method': self.source_method,
                           'sink_classname': self.sink_classname,
                           'sink_method': self.sink_method,
                           'sink_offset': self.sink_offset,
                           'path': self.path}, sort_keys=True)


class TaintedReg():
    ''' Representation of a tainted register '''

    def __init__(self, source, class_name: str = '', method_name: str = '', reg_id: int = -1, offset: int = -1):
        '''
        Constructor from TaintedReg, as Android uses different
        virtual registers for different methods, we need to store
        the reference of the class and the method where the
        register is used, the number of the register (basic),
        and we will store the offset to generate if necessary a trace
        of the tainting.

        :param class_name: class where the register is used.
        :param method_name: method where the register is used.
        :param reg_id: number of the register.
        :param offset: offset where taint starts.
        '''
        self.source = source
        self.class_name = class_name
        self.method_name = method_name
        self.reg_id = reg_id
        self.offset = offset


class TaintedField():
    ''' Representation of a tainted field (both instance and static fields) '''

    def __init__(self, source, class_name: str = '', field_name: str = ''):
        '''
        Cosntructor for a TaintedField object.
        '''
        self.source = source
        self.class_name = class_name
        self.field_name = field_name


class TaintedIntentExtra():
    ''' Representation of a tainted intent extra '''

    def __init__(self, source, intent: Intent = None):
        '''
        Constructor of a tainted intent extra

        The intent field is an instance of the type Instruction.Intent which
        already contains the target package name, class name, as well as the
        action and extras keys. We then store the ones that are tainted and
        should be tracked.
        '''
        self.source = source
        self.intent = intent
        self.tainted_keys = set()

    def taint_extra(self, key: str = ''):
        ''' Taint a given extra '''
        for extra in self.intent.extras:
            if key == extra[1]:
                self.tainted_keys.add(key)
                return

    def untaint_extra(self, key: str = ''):
        ''' Untaint a given extra '''
        for extra in self.intent.extras:
            if key == extra[1] and key in self.tainted_keys:
                self.tainted_keys.discard(key)
                return

    def is_tainted(self, key: str = ''):
        ''' Check if a given extra is tainted '''
        for extra in self.intent.extras:
            if key == extra[1] and key in self.tainted_keys:
                return True
        return False



class TaintEngine:
    ''' Main taint analysis engine '''

    def __init__(self, analysis: Analysis, sources: SourceSink, sinks: SourceSink, intents_targets: dict, debug: bool):
        '''
        Taint analysis engine constructor. We keep a reference to the
        current class and method being analyzed (as strings). The enging also
        contains a dictionary of TaintedReg objects.

        :param analysis: Analysis object for tainting registers from other methods.
        :param sources: the list of sources for the current analysis
        :param sinks: the list of sinks for the current analysis
        :param intents_targets: dictionary of intents detected in the bytecode
                                and their targets (used for broadcasted intents)
        :param debug: print debug messages or not
        '''
        self.analysis = analysis
        self.meth_analysis = None
        self.current_class = ""  # str(meth_analysis.get_class_name())
        self.current_method = ""  # str(meth_analysis.name)
        self.current_descriptor = ""  # str(meth_analysis.descriptor)
        self.method_stack = []

        self.tainted_registers = dict()
        self.tainted_fields = dict()
        self.tainted_extras = dict()
        self.tainted_intents = dict()

        self.sources = sources
        self.sources_protos = {"{}->{}{}".format(source.class_name,
                                                 source.method_name,
                                                 source.descriptor) for source in self.sources}
        self.sinks = sinks
        self.sinks_protos = {"{}->{}{}".format(sink.class_name,
                                               sink.method_name,
                                               sink.descriptor) for sink in self.sinks}
        self.intents_targets = intents_targets

        # a dictionary to keep track of values from different
        # registers, this will be useful to know the value from
        # a specific register in a given instruction
        self.symbol_table = dict()

        self.DEBUG = debug


    def save_state(self):
        """
        Save the current state, i.e., the current tainted
        elements, and returns it as a dictionary.

        :return: a dictionary representing the state
        """

        state = {
            "tainted_registers": self.tainted_registers,
            "tainted_fields": self.tainted_fields,
            "tainted_extras": self.tainted_extras,
            "tainted_intents": self.tainted_intents
        }

        return state


    def load_state(self, state):
        """
        Load a previously saved state

        Note that we merely check if the keys are present in
        the dictionary, but we do not check if the values are
        correct or not.

        :param state: dictionary, a previously saved state
        """
        if "tainted_registers" in state:
            self.tainted_registers = state["tainted_registers"]
        if "tainted_fields" in state:
            self.tainted_fields = state["tainted_fields"]
        if "tainted_extras" in state:
            self.tainted_extras = state["tainted_extras"]
        if "tainted_intents" in state:
            self.tainted_intent = state["tainted_intents"]


    def apply_taint_block(self, ir_block: dict, meth_analysis: MethodAnalysis, debug: bool, next_method_proto: str, ignore_call_inst=False):
        '''
        Apply thaint analysis to a whole block
        of lifted instructions, this method should
        check for calls to sources and sinks in order
        to apply tainting to the return value of the
        called source, and check the parameters of
        the called sinks in order to know if a tainted
        value has been passed as parameter.
        '''
        if len(ir_block) == 0:
            # No lifted instructions. Ignoring.
            return []

        self.meth_analysis = meth_analysis
        self.current_class = str(meth_analysis.get_class_name())
        self.current_method = str(meth_analysis.name)
        self.current_descriptor = str(meth_analysis.descriptor)
        self.last_instruction = None
        self.leaks = set()

        for idx, ir_instr in ir_block.items():
            if debug:
                print(ir_instr.disasm)
            if isinstance(ir_instr, CallInstruction):
                # TODO: this is just while we deal with recursion when doing
                # the propagation of internal methods. Will be removed.
                if not ignore_call_inst:
                    self.propagate_call_instruction(ir_instr, idx, next_method_proto)
            elif isinstance(ir_instr, BinaryInstruction):
                self.propagate_binary_instruction(ir_instr, idx)
            elif isinstance(ir_instr, UnaryInstruction):
                self.propagate_unary_instruction(ir_instr, idx)
            elif isinstance(ir_instr, ArrayInstruction):
                self.propagate_array_instruction(ir_instr, idx)
            elif isinstance(ir_instr, AssignmentInstruction):
                self.propagate_assignment_instruction(ir_instr, idx)
            elif isinstance(ir_instr, FieldInstruction):
                self.propagate_field_instruction(ir_instr, idx)
            elif isinstance(ir_instr, ReturnInstruction):
                self.propagate_implicit_call_instruction(ir_instr, idx)

        return self.leaks


    def taint_external_reg(self, source: str, reg_number: int, meth_analysis: MethodAnalysis):
        '''
        Method to taint a register from other method,
        for doing that we create a TaintReg object if
        it's not already in the dictionary, we will use
        the MethodAnalysis of the other method for getting
        the key.

        :param source: Source where the reg comes from.
        :param reg_number: register to taint.
        :param meth_analysis: Method analysis of the other object.
        :return: void
        '''
        current_class = str(meth_analysis.get_class_name())
        current_method = str(meth_analysis.name)
        key = (current_class, current_method, reg_number)
        if self.DEBUG:
            print("[+] Tainting external register %d" % (reg_number))
        if key not in self.tainted_registers.keys():
            self.tainted_registers[key] =       \
                TaintedReg(source, current_class, current_method, reg_number, 0)

    def taint_reg(self, source: str, reg_number: int, off: int):
        '''
        Method to taint a register, for doing that
        we will create a TaintedReg object if it's not
        already in the dictionary self.tainted_registers.

        :param source: Source where the taint comes from.
        :param reg_number: number of register.
        :param off: offset of instructions where register is tainted.
        :return: void
        '''
        if self.DEBUG:
            print("[+] Tainting register %d" % (reg_number))
        key = (self.current_class, self.current_method, reg_number)
        if key not in self.tainted_registers.keys():
            self.tainted_registers[key] =       \
                TaintedReg(source, self.current_class,
                           self.current_method, reg_number, off)

    def taint_reg_for_method(self, class_obj: ClassAnalysis, method_obj: MethodAnalysis, source: str, reg_number: int, off: int):
        '''
        Same behavior as the taint_reg method, except it
        taints the register for the method passed as argument.
        This is used when propagating implicit function calls.

        :param class_obj: ClassAnalysis object
        :param method_obj: MethodAnalysis object
        :param source: Source where the taint comes from.
        :param reg_number: number of register.
        :param off: offset of instructions where register is tainted.
        :return: void
        '''
        if self.DEBUG:
            print("[+] Tainting register %d" % (reg_number))
        key = (class_obj, method_obj, reg_number)
        if key not in self.tainted_registers.keys():
            self.tainted_registers[key] =       \
                TaintedReg(source, class_obj, method_obj, reg_number, off)

    def untaint_reg(self, reg_number: int):
        '''
        Sometimes a tainted value can be overwritten because of
        bad programming habits or who knows, compiler can generate
        code that overwrites a tainted register, so we do not need
        it anymore.

        :param reg_number: number of register to remove.
        '''
        if self.DEBUG:
            print("[+] Untainting register %d" % (reg_number))
        key = (self.current_class, self.current_method, reg_number)
        if key in self.tainted_registers.keys():
            del self.tainted_registers[key]

    def is_reg_tainted(self, reg_number: int) -> bool:
        '''
        Check if a register is already tainted or not,
        return a boolean as result.

        :param reg_number: register to check.
        '''
        return (self.current_class, self.current_method, reg_number) in self.tainted_registers


    def get_reg_source(self, reg_number: int) -> str:
        '''
        Get the source for a tainted register
        :param reg_number: register to check
        '''
        try:
            return self.tainted_registers[(self.current_class, self.current_method, reg_number)].source
        except KeyError:
            # It is possible that this is called for a register that is not
            # tainted, in that case the source is nothing
            return ""

    def taint_field(self, source: str, field_class: str, field_name: str):
        '''
        Taint a field given the class name and field name.
        We cannot use the current class name, as the accessed field can be from
        another class instance or a static field.

        :param source: Source where the taint comes from.
        :param field_class: the class name of the field
        :param field_name: the name of the field
        '''
        if self.DEBUG:
            print("Tainting field %s" % (field_name))
        key = (field_class, field_name)
        if key not in self.tainted_fields.keys():
            self.tainted_fields[key] = TaintedField(source, field_class, field_name)

    def untaint_field(self, field_class: str, field_name: str):
        '''
        Untaint a field given the class name and field name.

        :param field_class: the class name of the field
        :param field_name: the name of the field
        '''
        key = (field_class, field_name)
        if key in self.tainted_fields.keys():
            del self.tainted_fields[key]

    def is_field_tainted(self, key):
        '''
        Check if a field is tainted or not.

        :param key: a tuple (field_class, field_name)
        :return: boolean
        '''
        return key in self.tainted_fields.keys()

    def get_field_source(self, field_class: str, field_name: str) -> str:
        '''
        Get the source for a tainted field
        :param field_class: the name of the class that defines the field
        :param field_name: the name of the field
        '''
        try:
            return self.tainted_fields[((field_class, field_name))].source
        except KeyError:
            # It is possible that this is called for a register that is not
            # tainted, in that case the source is nothing
            return ""

    def taint_extra(self, source: str, intent: Intent, extra_key: str):
        '''
        Taint an extra given intent and key.

        :param source: Source where the taint comes from.
        :param intent: the intent that contains the extra
        :param extra_key: the key of the extra
        '''
        if self.DEBUG:
            print("Tainting extra key %s" % (extra_key))
        key = (intent, extra_key)
        intent_key = 'L{}/{};'.format(intent.target_pkg_name.replace('.', '/'),
                                      intent.target_class_name)
        if key not in self.tainted_extras.keys():
            self.tainted_extras[key] = TaintedIntentExtra(source, intent)
            self.tainted_extras[key].taint_extra(extra_key)

            # Broadcasted intents do not have a class name or package name
            if intent_key != 'L/;':
                self.tainted_intents[intent_key] = self.tainted_extras[key].intent
        else:
            # update values
            self.tainted_extras[key].taint_extra(extra_key)

            # Broadcasted intents do not have a class name or package name
            if intent_key != 'L/;':
                self.tainted_intents[intent_key] = self.tainted_extras[key].intent

    def untaint_extra(self, intent: Intent, extra_key: str):
        '''
        Untaint an extra given intent and key.

        :param intent: the intent that contains the extra
        :param extra_key: the key of the extra
        '''
        key = (intent, extra_key)
        if key in self.tainted_extras.keys():
            self.tainted_extras[key].untaint_extra(extra_key)

    def is_extra_tainted(self, value):
        '''
        Check if an extra is tainted or not.

        :param value: a tuple (intent, extra_key)
        :return: boolean
        '''
        if value not in self.tainted_extras:
            return False
        return self.tainted_extras[value].is_tainted(value[1])

    def is_tainted(self, value, value_type) -> bool:
        '''
        Check if any kind of value is tainted or not.

        :param value: value to check.
        :param value_type: type of the value to check.
        :return: boolean
        '''
        if value_type == 'register':
            return self.is_reg_tainted(value)
        elif value_type == 'field':
            return self.is_field_tainted(value)
        elif value_type == 'extra':
            return self.is_extra_tainted(value)

        return False

    def propagate_binary_instruction(self, instruction, offset):
        '''
        Propagate taint analysis in arithmetic and logic
        instructions, we will apply similar taint propagation
        rules to those in taintdroid.

        # T(Rresult) = T(Foperand) union T(Soperand)

        :param instruction: this should be one abstraction for arithmetic-logic instruction
        :param offset: offset of the instruction.
        '''
        if instruction.is_literal:
            # The /lit8 and /lit16 only use one register and one constant
            do_propagate = self.is_tainted(
                instruction.get_src_register(), 'register')
        elif instruction.is_to_address or instruction.is_literal:
            # The /2addr family only uses two registers
            do_propagate = self.is_tainted(instruction.get_src_register(), 'register') or       \
                self.is_tainted(instruction.get_dst_register(), 'register')
        else:
            do_propagate = self.is_tainted(instruction.get_src_register(), 'register') or       \
                self.is_tainted(
                    instruction.get_second_src_register(), 'register')

        if do_propagate:
            # Taint the destination register
            self.taint_reg(self.get_reg_source(instruction.get_src_register()),
                           instruction.get_dst_register(), offset)
        else:
            # Untaint the destination if needed
            self.untaint_reg(instruction.get_dst_register())

    def propagate_unary_instruction(self, instruction, offset):
        '''
        Propagate taint analysis in Unary instructions (NEG, NOT, Cast)

        # T(Rresult) = T(Soperand)

        :param instruction: `UnaryInstruction' instruction to apply tainting.
        :param offset: offset of the instruction.
        '''
        do_propagate = self.is_tainted(
            instruction.get_src_register(), 'register')

        if do_propagate:
            self.taint_reg(self.get_reg_source(instruction.get_src_register()),
                           instruction.get_dst_register(), offset)
        else:
            self.untaint_reg(instruction.get_dst_register())

    def propagate_call_instruction(self, instruction, offset, next_method_proto):
        '''
        Propagate taint analysis in Calls instructions, we must take care
        of the propagation through the parameter registers. To do that we
        must know which of the parameters are tainted, and which registers
        will be used as parameters in the called method.

        # call method(T(vX), T(vY), T(vZ)...)
                        |      |      |
                        v      v      v
               method(T(pX), T(pY), T(pZ)...)

        :param instruction: `CallInstruction' instruction with the call to
                            the method to apply tainting to its parameters.
        :param offset: offset of the instruction.
        '''
        # for applying tainting check first which of the registers that
        # are given as parameters are already tainted. Write them in a list
        # used late<<r for tainting the called methods by the offset of its
        # register
        tainted_offsets = []
        sources_offsets = []

        for i in range(len(instruction.get_parameters())):
            if i == 0 and instruction.get_kind() != "StaticCall":
                # first parameter is ``this'', we will not care about object
                tainted_offsets.append(False)
                sources_offsets.append("")
            else:
                reg = instruction.get_parameters()[i]
                tainted_offsets.append(self.is_tainted(reg, 'register'))
                sources_offsets.append(self.get_reg_source(reg))

        called_method = self.analysis.get_method_analysis_by_name(instruction.get_class(),
                                                                  instruction.get_method(),
                                                                  instruction.get_descriptor())
        # For AsyncTask the execute() or executeOnExecutor() methods have no
        # code. Instead we use the doInBackground() method for the propagation.
        if instruction.get_method() in {'execute', 'executeOnExecutor'}:
            # Get the class analysis object for the class called in the instruction object
            class_analysis = self.analysis.get_class_analysis(instruction.get_class())
            if class_analysis is None:
                return None

            # Check if the class extends AsyncTask
            if class_analysis.extends == 'Landroid/os/AsyncTask;':
                default_methods = dict()
                for method in class_analysis.get_methods():
                    # The bridge method is automatically added by the Java
                    # compiler, but does not really contain any code. We
                    # therefore ignore it.
                    if 'bridge' in method.get_access_flags_string():
                        continue

                    # We only need to doInBackground() method
                    if method.name != 'doInBackground':
                        continue

                    called_method = method

        if called_method is None:
            # Sanity check, should never happen
            return

        encoded_method = called_method.get_method()

        if isinstance(encoded_method, ExternalMethod) or                                \
                encoded_method.full_name.startswith('Landroid/') or                     \
                encoded_method.full_name.startswith('Landroidx/') or                    \
                encoded_method.full_name.startswith('Lcom/google/android/material/'):
            self.propagate_external_method_call_instruction(
                instruction, offset, tainted_offsets, sources_offsets)
        else:
            # TODO: maybe no need to propagate when the called method is a
            # source or a sink.

            """
            number_of_regs = 0
            number_of_params = 0

            # as androguard return weird information through "get_information" method
            # handle here the whole number of registers
            # then the number of parameters, the registers used by the parameters are
            # the last registers from those used by the method.
            #
            # e.g. number_of_regs = 5 = v0, v1, v2, v3 & v4
            # number_of_params = 3 = v2, v3, v4 (last registers from used registers)
            if 'registers' in encoded_method.get_information():
                number_of_regs = encoded_method.get_information()[
                    'registers'][1]
                if number_of_regs > 0:
                    number_of_regs += 1
            if 'params' in encoded_method.get_information().keys():
                number_of_params = len(
                    encoded_method.get_information()['params'])

            # check it's not static
            if encoded_method.get_access_flags() & 0x8 == 0:
                number_of_params += 1
                # some constructors are 0
                if number_of_regs != 0:
                    number_of_regs -= 1

            # get the reg_id for each one of the parameters (in prev example: v2, v3, v4)
            param_regs = [x for x in range(
                number_of_regs, number_of_regs + number_of_params)]

            # taint the registers from that method
            for i in range(len(param_regs)):
                if tainted_offsets[i]:
                    self.taint_external_reg(sources_offsets[i], param_regs[i], called_method)
            """
            # check if the method is static
            if encoded_method.get_access_flags() & 0x8 != 0:
                static_method = True
            else:
                static_method = False

            # TODO: problem here: we ignore too many parameters in some cases.
            # Make sure this is correct.
            method_info = encoded_method.get_information()
            regs_to_ignore = 0
            if not static_method:
                regs_to_ignore += 1
            # if 'return' in method_info.keys() and       \
            #         method_info['return'] != 'void':
            #     regs_to_ignore += 1

            instruction_params = instruction.get_parameters()[regs_to_ignore:]

            for idx, reg in enumerate(instruction_params):
                if self.is_tainted(reg, 'register'):
                    try:
                        source = self.get_reg_source(reg)
                        self.taint_external_reg(source,
                                                method_info['params'][idx][0],
                                                called_method)
                    except IndexError:
                        # TODO: this is related to the problem with ignored
                        # parameter registers, sometimes we do not ignore
                        # enough and end up with an IndexError
                        continue

            called_proto = '{}->{}{}'.format(encoded_method.full_name.split()[0],
                                             encoded_method.full_name.split()[1],
                                             encoded_method.full_name.split()[2])
            called_class_analysis = self.analysis.get_class_analysis(encoded_method.full_name.split()[0])
            # source_proto = '{}->{}{}'.format(self.sources.class_name,
            #                                  self.sources.method_name,
            #                                  self.sources.descriptor)

            if called_proto != next_method_proto and                                    \
                    called_proto not in self.sources_protos and                         \
                    called_class_analysis.extends != 'Landroid/os/AsyncTask;':

                current_class = self.current_class
                current_method = self.current_method
                current_descriptor = self.current_descriptor

                if self.DEBUG:
                    print('--- start propagate internal method ({})' .format(called_method.name))
                do_propagate = self.propagate_internal_method_call_instruction(
                        instruction, called_method, offset, tainted_offsets, sources_offsets)
                if self.DEBUG:
                    print('--- end propagate internal method ({})' .format(called_method.name))

                # Reverting attributes for the taint engine, which where
                # changed during the propagation of the internal method
                self.current_class = current_class
                self.current_method = current_method
                self.current_descriptor = current_descriptor

                dst_register = instruction.get_return_reg()
                if do_propagate:
                    self.taint_reg(self.get_reg_source(dst_register), dst_register, offset)
                else:
                    self.untaint_reg(dst_register)

        # start working with sources and sinks
        # in case you detect a source, taint its return
        # register, in case of a sink detect
        # if one of its parameters is tainted
        # in that case raise an alert.
        instruction_proto = "{}->{}{}".format(instruction.get_class(),
                                              instruction.get_method(),
                                              instruction.get_descriptor())
        # if self.sources.method_name == instruction.get_method() and \
        #     self.sources.class_name == instruction.get_class() and \
        #         self.sources.descriptor == instruction.get_descriptor():
        if instruction_proto in self.sources_protos:
            # source = self.sources.class_name + '->' + self.sources.method_name + self.sources.descriptor
            source = instruction_proto
            if self.DEBUG:
                print("Found call to source: %s" % (source))
                print("Tainting return value register: %d" % (instruction.get_return_reg()))
            self.taint_reg(source, instruction.get_return_reg(), offset)


        # if self.sinks.method_name == instruction.get_method() and \
        #     self.sinks.class_name == instruction.get_class() and \
        #         self.sinks.descriptor == instruction.get_descriptor():
        if instruction_proto in self.sinks_protos:
            # sink = self.sinks.class_name + '->' + self.sinks.method_name + self.sinks.descriptor
            sink = instruction_proto
            if self.DEBUG:
                print("Found call to sink: %s" % (sink))
                print("Checking if one of its parameter has been tainted")
            for i in range(len(tainted_offsets)):
                if tainted_offsets[i]:
                    leak = Leak(sources_offsets[i],
                                sink,
                                self.current_class,
                                self.current_method,
                                offset)
                    self.leaks.add(leak)
                    if self.DEBUG:
                        print("[!] ALERT: possible data leak -> %s " % (leak))

    def propagate_implicit_call_instruction(self, instruction, idx):
        '''
        Propagates "implicit" method calls.

        We call "implicit" method calls methods that are invoked automatically
        at the end of another method. A good example of this is for AsyncTask.
        Take an AsyncTask object that defines a doInBackground and a
        onPostExecture method. When the app reaches the end of the
        doInBackground method, it will automatically jump to the onPostExecute
        method, without any explicit call to that method.

        This method handle the propagation of tainted objects for such methods.
        It acts as if there was an explicit call to the method, and is called
        when we reach a "return*" statement at the end of a method that might
        implicitely call another method.

        :param instruction: `ReturnInstruction' the `Instruction' object.
        :param offset: offset of the instruction.
        '''

        # Classes we want to inspect
        classes_with_implicit_calls = {
            'Landroid/os/AsyncTask;':
                [
                    'onPreExecute',
                    'doInBackground',
                    # 'onProgressUpdate',
                    'onPostExecute'
                ],
        }

        # Get the class analysis object for the class called in the instruction
        # object and check if the class extends one of the classes that use
        # implicit calls
        class_analysis = self.analysis.get_class_analysis(self.current_class)
        if class_analysis is not None and class_analysis.extends in classes_with_implicit_calls:
            methods = classes_with_implicit_calls[class_analysis.extends]
            try:
                current_method_idx = methods.index(self.current_method)
            except ValueError:
                return

            next_methods = [item for item in methods
                            if methods.index(item) > current_method_idx]

            found_next_method = False
            for inext_method in next_methods:
                for method in class_analysis.get_methods():
                    # The bridge method is automatically added by the Java
                    # compiler, but does not really contain any code. We
                    # therefore ignore it.
                    if 'bridge' in method.get_access_flags_string():
                        continue

                    if method.name == inext_method:
                        next_method = method
                        found_next_method = True
                        break
                if found_next_method:
                    break

            # Check if we have the next method, if not we stop here
            if not found_next_method:
                return

            # Now we have the MethodAnalysis object for the next method that
            # will be called: we can do the propagation
            encoded_method = method.get_method()

            # We check if the current method returns a tainted object
            if self.is_tainted(instruction.get_return_register(), 'register'):
                if method.name != b'onProgressUpdate':
                    self.taint_reg_for_method(self.current_class,
                                              method.name,
                                              self.get_reg_source(instruction.get_return_register()),
                                              encoded_method.get_information()['params'][0][0],
                                              idx)

    def propagate_array_instruction(self, instruction, offset):
        '''
        Propagate taint analysis in array instructions.

        :param instruction: `ArrayInstruction' instruction with the array method
                            to the method to apply tainting to its parameters.
        :param offset: offset of the instruction.
        '''
        if instruction.get_kind() == 'aget':
            if self.is_tainted(instruction.get_array_register(), 'register'):
                # Do the propagation
                source = self.get_reg_source(instruction.get_array_register())
                self.taint_reg(source, instruction.get_src_or_dst_register(), offset)
            elif self.is_tainted(instruction.get_index_register(), 'register'):
                # Do the propagation
                source = self.get_reg_source(instruction.get_index_register())
                self.taint_reg(source, instruction.get_src_or_dst_register(), offset)
            else:
                self.untaint_reg(instruction.get_src_or_dst_register())

        elif instruction.get_kind() == 'aput':
            if self.is_tainted(instruction.get_src_or_dst_register(), 'register'):
                source = self.get_reg_source(instruction.get_src_or_dst_register())
                # Do the propagation
                self.taint_reg(source, instruction.get_array_register(), offset)
            elif self.is_tainted(instruction.get_array_register(), 'register'):
                source = self.get_reg_source(instruction.get_array_register())
                # Do the propagation
                self.taint_reg(source, instruction.get_array_register(), offset)
            else:
                self.untaint_reg(instruction.get_array_register())

    def propagate_assignment_instruction(self, instruction, offset):
        '''
        Method to propagate tainting in case of having an assignment
        instruction, we have different kind of assignment instructions:
        * RegAssignment
        * ResultAssignment
        * ExceptionAssignment
        * LiteralAssignment
        * StringAssignment
        * ClassAssignment

        For the moment we will apply the tainting for the RegAssignment as it
        involves two different registers, for others like StringAssignment we
        will insert its value in the symbolic table.
        '''

        if instruction.get_kind() == "RegAssignment":
            do_propagate = self.is_tainted(
                instruction.get_src_register(), 'register')

            if do_propagate:
                self.taint_reg(self.get_reg_source(instruction.get_src_register()),
                               instruction.get_dst_register(), offset)
            else:
                self.untaint_reg(instruction.get_dst_register())
        elif instruction.get_kind() == "StringAssignment":
            self.symbol_table[instruction.get_dst_register()
                              ] = instruction.get_src_string()
            self.untaint_reg(instruction.get_dst_register())
        elif instruction.get_kind() == "LiteralAssignment":
            self.symbol_table[instruction.get_dst_register()
                              ] = instruction.get_src_literal()
        elif instruction.get_kind() == "ResultAssignment":
            # To see if we should propagate, we look at the previous instruction
            # which is the invoke one and check whether the register is tainted
            if instruction.get_last_instr() is not None:
                src_register = instruction.get_last_instr().get_return_reg()
                do_propagate = self.is_tainted(src_register, 'register')
                if do_propagate:
                    self.taint_reg(self.get_reg_source(src_register),
                                   instruction.get_dst_register(), offset)
                else:
                    self.untaint_reg(instruction.get_dst_register())
        else:
            # other kind of instructions are not supported yet
            if self.DEBUG:
                print("Instruction of kind '%s' is not supported yet!" %
                      (instruction.get_kind()))
        return

    def propagate_field_instruction(self, instruction, offset):
        '''
        Perform the propagation for field operations on object instances (iget*
        and iput*) and static fields (sget* and sput*)

        :param instruction: instruction object
        :param offset: offset of the instruction
        '''
        if instruction.kind.endswith('put'):
            src_register = instruction.get_src_or_dst_register()
            if self.is_tainted(src_register, 'register'):
                self.taint_field(self.get_reg_source(src_register),
                                 instruction.get_field_class(),
                                 instruction.get_field_name())
            else:
                self.untaint_field(instruction.get_field_class(), instruction.get_field_name())
        elif instruction.kind.endswith('get'):
            dst_register = instruction.get_src_or_dst_register()
            field_class = instruction.get_field_class()
            field_name = instruction.get_field_name()
            if self.is_tainted((field_class, field_name), 'field'):
                self.taint_reg(self.get_field_source(field_class, field_name), dst_register, offset)
            else:
                self.untaint_reg(dst_register)

    def propagate_external_method_call_instruction(self, instruction, offset, tainted_offsets, sources_offsets):
        '''
        Method to handle cases of calls to external methods which cannot be analyzed
        directly by the tainted parameters (as it's not possible to retrieve the
        information of parameters from androguard).

        :param instruction: instruction from the ir to work with.
        :param offset: ???
        '''
        # Here we need to check if the call is to store or get an intent
        # extra, which might be tainted, or we might have to propagate the
        # tainting.
        proto = '{}->{}{}'.format(instruction.get_class(),
                                  instruction.get_method(),
                                  instruction.get_descriptor())

        # found a call to an android intent constructor,
        # get the intent object from the analysis and the
        # register for the symbol table.
        if proto.startswith('Landroid/content/Intent;-><init>'):
            intent_object = instruction.intent_object
            intent_register = instruction.get_parameters()[0]
            self.symbol_table[intent_register] = intent_object
            #print(intent_object)
            #print(instruction)
            #pprint.pprint(self.tainted_registers)
            #pprint.pprint(self.symbol_table)

        # found a call to putExtra
        # the second param can be any type and we will
        # check if its register is tainted, if it's
        # tainted, then taint the extra
        if proto.startswith('Landroid/content/Intent;->putExtra'):
            intent_reg = instruction.get_parameters()[0]
            extra_key_reg = instruction.get_parameters()[1]
            data_value_reg = instruction.get_parameters()[2]

            # check if data_value_reg is not tainted
            # if not, return
            if not self.is_tainted(data_value_reg, 'register'):
                return

            #print(proto)
            #print(intent_reg)
            #print(extra_key_reg)
            #print(data_value_reg)

            #print(self.is_tainted(data_value_reg, 'register'))
            #print(intent_reg in self.symbol_table.keys())
            #print(isinstance(self.symbol_table[intent_reg], Intent))
            #print(self.symbol_table[intent_reg])
            #pprint.pprint(self.symbol_table)
            #pprint.pprint(self.tainted_registers)

            # intent reg is not in symbol table, go back
            if intent_reg not in self.symbol_table.keys() \
                or not isinstance(self.symbol_table[intent_reg], Intent):
                return

            # in case it is tainted
            intent_obj = self.symbol_table[intent_reg]
            for extra_value_reg, extra_key in intent_obj.extras:
                if self.symbol_table[extra_key_reg] == extra_key:
                    source = self.get_reg_source(extra_value_reg)
                    self.taint_extra(source, intent_obj, extra_key)

        # check if the call to getExtras comes from a tainted intent
        # for that we will use the current class as check for key in
        # self.tainted_intents
        if instruction.get_class() == "Landroid/content/Intent;" and                \
                instruction.get_method().startswith('get') and                      \
                (instruction.get_method().endswith('Extra') or                      \
                instruction.get_method().endswith('Extras')) and                    \
                instruction.get_descriptor() in {'(Ljava/lang/String;)Z',
                                                 '(Ljava/lang/String;)B',
                                                 '(Ljava/lang/String;)C',
                                                 '(Ljava/lang/String;)S',
                                                 '(Ljava/lang/String;)I',
                                                 '(Ljava/lang/String;)J',
                                                 '(Ljava/lang/String;)F',
                                                 '(Ljava/lang/String;)D',
                                                 '(Ljava/lang/String;)Ljava/lang/String;',
                                                 '(Ljava/lang/String;)Ljava/lang/CharSequence',
                                                 '(Ljava/lang/String;)Landroid/os/Parcelable',
                                                 '(Ljava/lang/String;)[Landroid/os/Parcelable',
                                                 '(Ljava/lang/String;)Ljava/io/Serializable;',
                                                 '(Ljava/lang/String;)[Z',
                                                 '(Ljava/lang/String;)[B',
                                                 '(Ljava/lang/String;)[S',
                                                 '(Ljava/lang/String;)[C',
                                                 '(Ljava/lang/String;)[I',
                                                 '(Ljava/lang/String;)[J',
                                                 '(Ljava/lang/String;)[F',
                                                 '(Ljava/lang/String;)[D',
                                                 '(Ljava/lang/String;)[Ljava/lang/String;',
                                                 '(Ljava/lang/String;)[Ljava/lang/CharSequence',
                                                 '(Ljava/lang/String;)Landroid/os/Bundle;',
                                                 '()Landroid/os/Bundle;'}:
            if self.current_class not in self.tainted_intents.keys():
                return

            # now if we know intent is tainted, taint the destination
            # register from the call to getExtras()
            intent_reg = instruction.get_parameters()[0]

            # Ugly hack to get the source, as we do not save TaintedIntent
            # We need to use the Intent to find the corresponding TaintedIntentExtra
            for x in list(self.tainted_extras.keys()):
                if self.tainted_intents[self.current_class] == x[0]:
                    source = self.tainted_extras[x].source
            self.taint_reg(source, instruction.get_return_reg(), offset)

        # Check if the call to Landroid/os/Bundle;->get* comes from
        # a tainted bundle (tainted register), in that case analyze
        # the extra key and check if is tainted.
        if proto.startswith("Landroid/os/Bundle;->get"):
            if not self.is_tainted(instruction.get_parameters()[0], 'register'):
                return
            extra_key = self.symbol_table[instruction.get_parameters()[1]]

            intent_obj = self.tainted_intents[self.current_class]

            if self.is_extra_tainted((intent_obj,extra_key)):
                source = self.get_reg_source(instruction.get_parameters()[0])
                self.taint_reg(source, instruction.get_return_reg(), offset)

        if proto.split('>')[1] in               \
                {'sendBroadcast(Landroid/content/Intent; Ljava/lang/String;)V',
                 'sendBroadcast(Landroid/content/Intent;)V',
                 'sendBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle;)V',
                 'sendBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Ljava/lang/String;)V',
                 'sendBroadcastWithMultiplePermissions(Landroid/content/Intent; [Ljava/util/String;)V',
                 'sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V',
                 'sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V',
                 'sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String;)V',
                 'sendOrderedBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V',
                 'sendStickyBroadcast(Landroid/content/Intent;)V',
                 'sendStickyBroadcast(Landroid/content/Intent; Landroid/os/Bundle)V',
                 'sendStickyBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle;)V',
                 'sendStickyOrderedBroadcast(Landroid/content/Intent; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V',
                 'sendStickyOrderedBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V'}:
            # Here we move the "anonymous" intent extras into the tainted
            # intents since we now know the source and target

            # We loop across all intents targets to see if we have the right one
            for target, intents in self.intents_targets.items():
                try:
                    for intent in intents[(self.current_class, self.current_method)]:
                        if offset == intent.where_used:
                            # We found a match! This means that the intent that
                            # is used as argument of the current prototype must
                            # be tainted.

                            # These methods are called with invoke-virtual, so
                            # their first argument is "this", the second
                            # argument is the intent
                            intent_reg = instruction.get_parameters()[1]

                            if not isinstance(self.symbol_table[intent_reg], Intent):
                                if self.DEBUG:
                                    print('Error: no intent at register {} in the symbol table'.format(intent_reg))
                                continue

                            intent_key = 'L{};'.format(target.replace('.', '/'))
                            self.tainted_intents[intent_key] = self.symbol_table[intent_reg]
                except KeyError:
                    # No intents for this source
                    continue

        if instruction.get_class() == "Landroid/content/Intent;" and \
            instruction.get_method().startswith('toUri'):

            key = "{}->{}".format(self.current_class, self.current_method)

            # check if the intent used in the call is tainted
            if key in self.tainted_intents.keys():
                for tuple_ in self.tainted_extras.keys():
                    if tuple_[0] == self.tainted_intents[key]:
                        source = self.tainted_extras[tuple_].source
                        # if tainted, taint the result register
                        self.taint_reg(source, instruction.get_return_reg(), offset)
                        break
        # Probably not necessary this code
        # maybe I will remove it later
        # !!!!!!!!!!!!!!!!!!!!!!

        # if proto.endswith('startService(Landroid/content/Intent;)Landroid/content/ComponentName;'):
        #     intent_reg = instruction.get_parameters()[1]
        #     # intent reg is not in symbol table, go back
        #     if intent_reg not in self.symbol_table.keys() or not isinstance(self.symbol_table[intent_reg], Intent):
        #         return
        #     intent_obj = self.symbol_table[intent_reg]


        # For other ExternalMethod (those that are not in the DEX/APK)
        # we follow a conservative approach, if one of the parameters
        # is tainted, taint the registers which hold the return value.
        if True in tainted_offsets:
            source = ' / '.join([x for x in sources_offsets if x != ""])
            self.taint_reg(source, instruction.get_return_reg(), offset)

    def propagate_internal_method_call_instruction(self, instruction, method_obj, offset, tainted_offsets, sources_offsets):
        # Instance of DEXLifter
        dex_lifter = DexLifter()

        # Lift method's instructions
        lifted_instructions = dex_lifter.lift_method_blocks(method_obj.get_basic_blocks())

        # Save current set of leaks
        # Calling `apply_taint_block' will reset the set of leaks, which we
        # obviously do not want to happen
        current_leaks = {i for i in self.leaks}

        # Apply tainting rules
        self.apply_taint_block(lifted_instructions,
                               method_obj,
                               self.DEBUG,              # debug
                               None,                    # next_method_proto
                               ignore_call_inst=True)

        # Restoring leaks
        for leak in current_leaks:
            self.leaks.add(leak)

        # Check if the returned register is tainted
        try:
            last_index = max(lifted_instructions.keys())
            last_instruction = lifted_instructions[last_index]

            if isinstance(last_instruction, ReturnInstruction):
                return_register = last_instruction.get_return_register()
                return self.is_tainted(return_register, 'register')
            else:
                return False
        except ValueError:
            return False


if __name__ == '__main__':
    # TODO: delete me
    try:
        #apk, _, analysis = AnalyzeAPK(sys.argv[1])
        _, _, analysis = AnalyzeDex(sys.argv[1])
    except Exception as exc:
        sys.exit()

    for method in analysis.get_methods():
        engine = TaintEngine(method, analysis)

        for i in range(10):
            engine.taint_reg(i, i+5)

        m = method.get_method()
        for idx, inst in m.get_instructions_idx():
            op_value = inst.get_op_value()

            if op_value in CALL_OPERATIONS:
                call_inst = CallInstruction(op_value, inst.get_operands())
                engine.propagate_call_instruction(call_inst, idx)
            '''
            if op_value in {0x90, 0x9b, 0xd0, 0xd8, 0x91, 0x9c, 0x92, 0x9d,
                    0xd2, 0xda, 0x93, 0x9e, 0xd3, 0xdb, 0x94, 0x9f, 0xd4,
                    0xdc, 0xb0, 0xbb, 0xb1, 0xbc, 0xb2, 0xbd, 0xb3, 0xbe,
                    0xb4, 0xbf, 0xc6, 0xcb, 0xc7, 0xcc, 0xc8, 0xcd, 0xc9,
                    0xce, 0xca, 0xcf, 0xa6, 0xab, 0xa7, 0xac, 0xa8, 0xad,
                    0xa9, 0xae, 0xaa, 0xaf, 0x95, 0xa0, 0xd5, 0xdd, 0x96,
                    0xa1, 0xd6, 0xde, 0x97, 0xa2, 0xd7, 0xdf}:
                bin_inst = BinaryInstruction(op_value, inst.get_operands(),
                        "Aritmethical", "int")
                engine.propagate_binary_instruction(bin_inst, idx)
                sys.exit()
            '''
