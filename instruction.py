#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pprint

from intent import Intent

# TODO: make that a CLI argument or something
DEBUG = False

# TODO: we could probably merge some of these arrays
ARITHMETIC_INT_OPERATIONS = {0x90, 0x91, 0x92, 0x93, 0x94, 0x9b, 0x9c,
                             0x9d, 0x9e, 0x9f, 0xd0, 0xd1, 0xd2, 0xd3,
                             0xd4, 0xd8, 0xd9, 0xda, 0xdb, 0xdc}
ARITHMETIC_INT_OPERATIONS_TOADDR = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4,
                                    0xbb, 0xbc, 0xbd, 0xbe, 0xbf}
ARITHMETIC_DOUBLE_OPERATIONS_TOADDR = {0xb5, 0xb6, 0xb7, 0xc0, 0xc1, 0xc2,
                                       0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
                                       0xcc, 0xcd, 0xce, 0xcf}
ARITHMETIC_DOUBLE_OPERATIONS = {0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
                                0xab, 0xac, 0xad, 0xae, 0xaf}

LOGICAL_OPERATIONS = {0x95, 0x96, 0x97, 0xa0, 0xa1, 0xa2,
                      0xd5, 0xd6, 0xd7, 0xdd, 0xde, 0xdf}
SHIFT_UNARY_OPERATIONS = {0x98, 0x99, 0x9a, 0xa3, 0xa4,
                          0xa5, 0xe0, 0xe1, 0xe2}
SHIFT_BINARY_OPERATIONS = {0xb8, 0xb9, 0xba, 0xc3, 0xc4, 0xc5}
UNARY_OPERATIONS = {0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80}
CAST_OPERATIONS = {0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
                   0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f}
CALL_OPERATIONS = {0x6e, 0x6f, 0x70, 0x71, 0x72,
                   0x74, 0x75, 0x76, 0x77, 0x78}
ARRAY_OPERATIONS = {0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
                    0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51}
FIELD_OPERATIONS = {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d}
RETURN_OPERATIONS = {0x0e, 0x0f, 0x10, 0x11}

MOVE_REG_OPERATIONS = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
MOVE_RESULT_OPERATIONS = {0x0a, 0x0b, 0x0c}
MOVE_EXCEPTION = {0x0d}
MOVE_LITERAL = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}
MOVE_STRING = {0x1a, 0x1b}
MOVE_CLASS = {0x1c}
MOV_OPERATIONS = set.union(MOVE_REG_OPERATIONS, MOVE_RESULT_OPERATIONS,
                           MOVE_EXCEPTION, MOVE_LITERAL, MOVE_STRING, MOVE_CLASS)

DALVIK_INSTRUCTION_NAMES = {
    0x00: 'nop',
    0x01: 'move',
    0x02: 'move/from16',
    0x03: 'move/16',
    0x04: 'move-wide',
    0x05: 'move-wide/from16',
    0x06: 'move-wide/16',
    0x07: 'move-object',
    0x08: 'move-object/from16',
    0x09: 'move-object/16',
    0x0a: 'move-result',
    0x0b: 'move-result-wide',
    0x0c: 'move-result-object',
    0x0d: 'move-exception',
    0x0e: 'return-void',
    0x0f: 'return',
    0x10: 'return-wide',
    0x11: 'return-object',
    0x12: 'const/4',
    0x13: 'const/16',
    0x14: 'const',
    0x15: 'const/high16',
    0x16: 'const-wide/16',
    0x17: 'const-wide/32',
    0x18: 'const-wide',
    0x19: 'const-wide/high16',
    0x1a: 'const-string',
    0x1b: 'const-string/jumbo',
    0x1c: 'const-class',
    0x1d: 'monitor-enter',
    0x1e: 'monitor-exit',
    0x1f: 'check-cast',
    0x20: 'instance-of',
    0x21: 'array-length',
    0x22: 'new-instance',
    0x23: 'new-array',
    0x24: 'filled-new-array',
    0x25: 'filled-new-array/range',
    0x26: 'fill-array-data',
    0x27: 'throw',
    0x28: 'goto',
    0x29: 'goto/16',
    0x2a: 'goto/32',
    0x2b: 'packed-switch',
    0x2c: 'sparse-switch',
    0x2d: 'cmpl-float',
    0x2e: 'cmpg-float',
    0x2f: 'cmpl-double',
    0x30: 'cmpg-double',
    0x31: 'cmp-long',
    0x32: 'if-eq',
    0x33: 'if-ne',
    0x34: 'if-lt',
    0x35: 'if-ge',
    0x36: 'if-gt',
    0x37: 'if-le',
    0x38: 'if-eqz',
    0x39: 'if-nez',
    0x3a: 'if-ltz',
    0x3b: 'if-gez',
    0x3c: 'if-gtz',
    0x3d: 'if-lez',
    0x3e: 'unused',
    0x3f: 'unused',
    0x40: 'unused',
    0x41: 'unused',
    0x42: 'unused',
    0x43: 'unused',
    0x44: 'aget',
    0x45: 'aget-wide',
    0x46: 'aget-object',
    0x47: 'aget-boolean',
    0x48: 'aget-byte',
    0x49: 'aget-char',
    0x4a: 'aget-short',
    0x4b: 'aput',
    0x4c: 'aput-wide',
    0x4d: 'aput-object',
    0x4e: 'aput-boolean',
    0x4f: 'aput-byte',
    0x50: 'aput-char',
    0x51: 'aput-short',
    0x52: 'iget',
    0x53: 'iget-wide',
    0x54: 'iget-object',
    0x55: 'iget-boolean',
    0x56: 'iget-byte',
    0x57: 'iget-char',
    0x58: 'iget-short',
    0x59: 'iput',
    0x5a: 'iput-wide',
    0x5b: 'iput-object',
    0x5c: 'iput-boolean',
    0x5d: 'iput-byte',
    0x5e: 'iput-char',
    0x5f: 'iput-short',
    0x60: 'sget',
    0x61: 'sget-wide',
    0x62: 'sget-object',
    0x63: 'sget-boolean',
    0x64: 'sget-byte',
    0x65: 'sget-char',
    0x66: 'sget-short',
    0x67: 'sput',
    0x68: 'sput-wide',
    0x69: 'sput-object',
    0x6a: 'sput-boolean',
    0x6b: 'sput-byte',
    0x6c: 'sput-char',
    0x6d: 'sput-short',
    0x6e: 'invoke-virtual',
    0x6f: 'invoke-super',
    0x70: 'invoke-direct',
    0x71: 'invoke-static',
    0x72: 'invoke-interface',
    0x73: 'unused',
    0x74: 'invoke-virtual/range',
    0x75: 'invoke-super/range',
    0x76: 'invoke-direct/range',
    0x77: 'invoke-static/range',
    0x78: 'invoke-interface/range',
    0x79: 'unused',
    0x7a: 'unused',
    0x7b: 'neg-int',
    0x7c: 'not-int',
    0x7d: 'neg-long',
    0x7e: 'not-long',
    0x7f: 'neg-float',
    0x80: 'neg-double',
    0x81: 'int-to-long',
    0x82: 'int-to-float',
    0x83: 'int-to-double',
    0x84: 'long-to-int',
    0x85: 'long-to-float',
    0x86: 'long-to-double',
    0x87: 'float-to-int',
    0x88: 'float-to-long',
    0x89: 'float-to-double',
    0x8a: 'double-to-int',
    0x8b: 'double-to-long',
    0x8c: 'double-to-float',
    0x8d: 'int-to-byte',
    0x8e: 'int-to-char',
    0x8f: 'int-to-short',
    0x90: 'add-int',
    0x91: 'sub-int',
    0x92: 'mul-int',
    0x93: 'div-int',
    0x94: 'rem-int',
    0x95: 'and-int',
    0x96: 'or-int',
    0x97: 'xor-int',
    0x98: 'shl-int',
    0x99: 'shr-int',
    0x9a: 'ushr-int',
    0x9b: 'add-long',
    0x9c: 'sub-long',
    0x9d: 'mul-long',
    0x9e: 'div-long',
    0x9f: 'rem-long',
    0xa0: 'and-long',
    0xa1: 'or-long',
    0xa2: 'xor-long',
    0xa3: 'shl-long',
    0xa4: 'shr-long',
    0xa5: 'ushr-long',
    0xa6: 'add-float',
    0xa7: 'sub-float',
    0xa8: 'mul-float',
    0xa9: 'div-float',
    0xaa: 'rem-float',
    0xab: 'add-double',
    0xac: 'sub-double',
    0xad: 'mul-double',
    0xae: 'div-double',
    0xaf: 'rem-double',
    0xb0: 'add-int/2addr',
    0xb1: 'sub-int/2addr',
    0xb2: 'mul-int/2addr',
    0xb3: 'div-int/2addr',
    0xb4: 'rem-int/2addr',
    0xb5: 'and-int/2addr',
    0xb6: 'or-int/2addr',
    0xb7: 'xor-int/2addr',
    0xb8: 'shl-int/2addr',
    0xb9: 'shr-int/2addr',
    0xba: 'ushr-int/2addr',
    0xbb: 'add-long/2addr',
    0xbc: 'sub-long/2addr',
    0xbd: 'mul-long/2addr',
    0xbe: 'div-long/2addr',
    0xbf: 'rem-long/2addr',
    0xc0: 'and-long/2addr',
    0xc1: 'or-long/2addr',
    0xc2: 'xor-long/2addr',
    0xc3: 'shl-long/2addr',
    0xc4: 'shr-long/2addr',
    0xc5: 'ushr-long/2addr',
    0xc6: 'add-float/2addr',
    0xc7: 'sub-float/2addr',
    0xc8: 'mul-float/2addr',
    0xc9: 'div-float/2addr',
    0xca: 'rem-float/2addr',
    0xcb: 'add-double/2addr',
    0xcc: 'sub-double/2addr',
    0xcd: 'mul-double/2addr',
    0xce: 'div-double/2addr',
    0xcf: 'rem-double/2addr',
    0xd0: 'add-int/lit16',
    0xd1: 'rsub-int',
    0xd2: 'mul-int/lit16',
    0xd3: 'div-int/lit16',
    0xd4: 'rem-int/lit16',
    0xd5: 'and-int/lit16',
    0xd6: 'or-int/lit16',
    0xd7: 'xor-int/lit16',
    0xd8: 'add-int/lit8',
    0xd9: 'rsub-int/lit8',
    0xda: 'mul-int/lit8',
    0xdb: 'div-int/lit8',
    0xdc: 'rem-int/lit8',
    0xdd: 'and-int/lit8',
    0xde: 'or-int/lit8',
    0xdf: 'xor-int/lit8',
    0xe0: 'shl-int/lit8',
    0xe1: 'shr-int/lit8',
    0xe2: 'ushr-int/lit8',
    0xe3: 'unused',
    0xe4: 'unused',
    0xe5: 'unused',
    0xe6: 'unused',
    0xe7: 'unused',
    0xe8: 'unused',
    0xe9: 'unused',
    0xea: 'unused',
    0xeb: 'unused',
    0xec: 'unused',
    0xed: 'unused',
    0xee: 'unused',
    0xef: 'unused',
    0xf0: 'unused',
    0xf1: 'unused',
    0xf2: 'unused',
    0xf3: 'unused',
    0xf4: 'unused',
    0xf5: 'unused',
    0xf6: 'unused',
    0xf7: 'unused',
    0xf8: 'unused',
    0xf9: 'unused',
    0xfa: 'invoke-polymorphic',
    0xfb: 'invoke-polymorphic/range',
    0xfc: 'invoke-custom',
    0xfd: 'invoke-custom/range',
    0xfe: 'const-method-handle',
    0xff: 'const-method-type',
    0x0100: 'packed-switch-payload',
    0x0200: 'sparse-switch-payload',
    0x0300: 'fill-array-data-payload',
    0xf2ff: 'invoke-object-init/jumbo',
    0xf3ff: 'iget-volatile/jumbo',
    0xf4ff: 'iget-wide-volatile/jumbo',
    0xf5ff: 'iget-object-volatile/jumbo',
    0xf6ff: 'iput-volatile/jumbo',
    0xf7ff: 'iput-wide-volatile/jumbo',
    0xf8ff: 'iput-object-volatile/jumbo',
    0xf9ff: 'sget-volatile/jumbo',
    0xfaff: 'sget-wide-volatile/jumbo',
    0xfbff: 'sget-object-volatile/jumbo',
    0xfcff: 'sput-volatile/jumbo',
    0xfdff: 'sput-wide-volatile/jumbo',
    0xfeff: 'sput-object-volatile/jumbo',
    0xffff: 'throw-verification-error/jumbo',
}


def intent_class_analysis(basic_block, ir_block: dict):
    '''
    Method to apply analysis to the ir block
    in order to discover intents used.
    '''
    reversed_idx_keys = sorted(ir_block.keys(), reverse=True)

    intent_aux = None
    intent_reg = None
    extra_key_reg = None
    extra_key_value = None
    extra_val_reg = None
    class_name_reg = None
    package_name_reg = None

    # we will apply a backward analysis of the basic block
    for idx in reversed_idx_keys:
        instr = ir_block[idx]

        if isinstance(instr, CallInstruction):
            # "whatever"->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
            if instr.get_method() == "startService" \
                and instr.get_descriptor() == "(Landroid/content/Intent;)Landroid/content/ComponentName;":

                intent_aux = Intent()
                intent_reg = instr.get_parameters()[1]

            # "whatever"->bindService
            elif instr.get_method() == "bindService" \
                    and instr.get_descriptor() in {"(Landroid/content/Intent; Landroid/content/ServiceConnection; I)Z"}:
                intent_aux = Intent()
                intent_reg = instr.get_parameters()[1]

            # "whatever"->startActivity
            elif instr.get_method() == "startActivity" \
                and instr.get_descriptor() in {"(Landroid/content/Intent;)V",
                                               "(Landroid/content/Intent; Landroid/os/Bundle;)V",
                                               "(Landroid/content/Intent; I)V",
                                               "(Landroid/content/Intent; I Landroid/os/Bundle;)V"}:

                intent_aux = Intent()
                intent_reg = instr.get_parameters()[1]

            # "whatever"->startActivityForResult
            elif instr.get_method() == "startActivityForResult" \
                and instr.get_descriptor() in {"(Landroid/content/Intent; I)V",
                                               "(Landroid/content/Intent; I Landroid/os/Bundle;)V"}:

                intent_aux = Intent()
                intent_reg = instr.get_parameters()[1]

            # Broadcasted intents
            elif '{}{}'.format(instr.get_method(), instr.get_descriptor()) in \
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

                intent_aux = Intent()
                intent_reg = instr.get_parameters()[1]

            # Landroid/content/Intent;-><init>
            elif instr.get_method() == "<init>" \
                and instr.get_class() == "Landroid/content/Intent;":
                
                if instr.get_parameters()[0] == intent_reg:
                    # We have found the constructor of an intent
                    # check if the returned register is the one
                    # used on startService and save the intent.
                    if intent_aux is not None:
                        instr.intent_object = intent_aux
                        intent_aux = None
            
            # Landroid/content/Intent;->putExtra
            elif instr.get_method() == "putExtra" \
                and instr.get_class() == "Landroid/content/Intent;" \
                and instr.get_descriptor() in {'(Ljava/lang/String; Z)Landroid/content/Intent;',
                                               '(Ljava/lang/String; B)Landroid/content/Intent;',
                                               '(Ljava/lang/String; C)Landroid/content/Intent;',
                                               '(Ljava/lang/String; S)Landroid/content/Intent;',
                                               '(Ljava/lang/String; I)Landroid/content/Intent;',
                                               '(Ljava/lang/String; J)Landroid/content/Intent;',
                                               '(Ljava/lang/String; F)Landroid/content/Intent;',
                                               '(Ljava/lang/String; D)Landroid/content/Intent;',
                                               '(Ljava/lang/String; Ljava/lang/String;)Landroid/content/Intent;',
                                               '(Ljava/lang/String; Ljava/lang/CharSequence)Landroid/content/Intent;',
                                               '(Ljava/lang/String; Landroid/os/Parcelable)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [Landroid/os/Parcelable)Landroid/content/Intent;',
                                               '(Ljava/lang/String; Ljava/io/Serializable;)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [Z)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [B)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [S)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [C)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [I)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [J)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [F)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [D)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [Ljava/lang/String;)Landroid/content/Intent;',
                                               '(Ljava/lang/String; [Ljava/lang/CharSequence)Landroid/content/Intent;',
                                               '(Ljava/lang/String; Landroid/os/Bundle;)Landroid/content/Intent;'}:

                # check if the putExtra is done for the current intent
                if instr.get_parameters()[0] == intent_reg:
                    extra_key_reg = instr.get_parameters()[1]
                    extra_val_reg = instr.get_parameters()[2]
            
            # Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
            elif instr.get_method() == "setClassName" \
                and instr.get_descriptor() == "(Ljava/lang/String; Ljava/lang/String;)Landroid/content/Intent;" \
                and instr.get_class() == "Landroid/content/Intent;":

                # check if the setClassName is done for the current intent
                if instr.get_parameters()[0] == intent_reg:
                    package_name_reg = instr.get_parameters()[1]
                    class_name_reg = instr.get_parameters()[2]
            
            # Landroid/content/Intent;->setClassName(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;
            elif instr.get_method() == "setClassName" \
                and instr.get_descriptor() == "(Landroid/content/Context; Ljava/lang/String;)Landroid/content/Intent;" \
                and instr.get_class() == "Landroid/content/Intent;":

                # check if the setClassName is done for the current intent
                if instr.get_parameters()[0] == intent_reg:
                    class_name_reg = instr.get_parameters()[2]
                    # this time there's not package name

        elif isinstance(instr, AssignmentInstruction):
            # a possible const-string for an extra of the intent
            # const-string vX, ""

            if instr.get_kind() == "StringAssignment" and instr.get_dst_register() == extra_key_reg:
                # Found an extra key, add it and set extra_key_reg to None
                extra_key_value = instr.get_src_string()
                intent_aux.extras.add((extra_val_reg, extra_key_value))
                extra_key_reg = None
                extra_key_value = None
                '''
                block_info = basic_block.get_method().get_information()
                if 'params' in block_info:
                    for item in block_info['params']:
                        if extra_val_reg == item[0]:
                            # The extra register is a function parameter,
                            # we won't find it through const-*
                            intent_aux.extras.add((extra_val_reg, extra_key_value))
                            extra_val_reg = None
                            extra_key_value = None
                            break               
                '''             

            if instr.get_kind() == "StringAssignment" and instr.get_dst_register() == extra_val_reg:
                # Found an extra value, add it and set extra_val_reg to None
                if extra_key_value is not None:
                    intent_aux.extras.add((instr.get_dst_register(), extra_key_value))
                    extra_val_reg = None
                    extra_key_value = None

            # a possible const-string for a class name
            # const-string vX, ""
            if instr.get_kind() == "StringAssignment" and instr.get_dst_register() == class_name_reg:
                intent_aux.target_class_name = instr.get_src_string()
                class_name_reg = None

            # a possible const-string for the package name
            # const-string vX, ""
            if instr.get_kind() == "StringAssignment" and instr.get_dst_register() == package_name_reg:
                intent_aux.target_pkg_name = instr.get_src_string()
                package_name_reg = None



class DexLifter:

    def __init__(self) -> None:
        self.intents = set()  # TODO: unused

    def lift_method_blocks(self, blocks: list):
        """
        Lift instructions from a basic block given
        from androguard instructions. This will be
        used by the Taint Engine in order to apply
        tainting rules.
        """
        # TODO: this method could be static
        lifted_instructions = dict()

        idx = 0
        last_call_instr = None
        for instr_block in blocks:
            try:
                instructions = list(instr_block.get_instructions())
            except AttributeError:
                # Happens for dummy blocks added for methods that have no code,
                # such as the execute function for AsyncTasks
                continue

            for instr in instructions:
                op_value = instr.get_op_value()
                operands = instr.get_operands()
                disasm = instr.disasm()

                if op_value in CALL_OPERATIONS:
                    instruction = CallInstruction(op_value, operands, disasm, instr.get_length())
                    #print("%d: CallInstruction" % (idx))
                    # set last call instruction for next move-result
                    # just if return type is not void
                    if instruction.get_return_type() != 'void':
                        last_call_instr = instruction
                elif op_value in ARITHMETIC_INT_OPERATIONS or op_value in ARITHMETIC_INT_OPERATIONS_TOADDR:
                    instruction = BinaryInstruction(
                        op_value, operands, disasm, "Aritmethical", "int")
                    #print("%d: ARITHMETIC_INT_OPERATIONS|ARITHMETIC_INT_OPERATIONS_TOADDR" % (idx))
                elif op_value in ARITHMETIC_DOUBLE_OPERATIONS or op_value in ARITHMETIC_DOUBLE_OPERATIONS_TOADDR:
                    instruction = BinaryInstruction(
                        op_value, operands, disasm, "Arithmetical", "float")
                    #print("%d: ARITHMETIC_DOUBLE_OPERATIONS|ARITHMETIC_DOUBLE_OPERATIONS_TOADDR" % (idx))
                elif op_value in LOGICAL_OPERATIONS:
                    instruction = BinaryInstruction(
                        op_value, operands, disasm, "Logical", "int")
                    #print("%d: LOGICAL_OPERATIONS" % (idx))
                elif op_value in SHIFT_UNARY_OPERATIONS:
                    instruction = ShiftInstruction(op_value, operands, disasm, "Unary")
                    #print("%d: SHIFT_UNARY_OPERATIONS" % (idx))
                elif op_value in SHIFT_BINARY_OPERATIONS:
                    instruction = ShiftInstruction(op_value, operands, disasm, "Binary")
                    #print("%d: SHIFT_BINARY_OPERATIONS" % (idx))
                elif op_value in UNARY_OPERATIONS:
                    instruction = UnaryInstruction(op_value, operands, disasm, "Unary")
                    #print("%d: UNARY_OPERATIONS" % (idx))
                elif op_value in CAST_OPERATIONS:
                    instruction = UnaryInstruction(op_value, operands, disasm, "Cast")
                    #print("%d: CAST_OPERATIONS" % (idx))
                elif op_value in ARRAY_OPERATIONS:
                    instruction = ArrayInstruction(op_value, operands, disasm)
                    #print("%d: ARRAY_OPERATIONS" % (idx))
                elif op_value in MOV_OPERATIONS:
                    instruction = AssignmentInstruction(op_value, operands, disasm)
                    if instruction.get_kind() == "ResultAssignment" and last_call_instr is not None:
                        instruction.set_last_instr(last_call_instr)
                        last_call_instr = None
                elif op_value in FIELD_OPERATIONS:
                    instruction = FieldInstruction(op_value, operands, disasm)
                elif op_value in RETURN_OPERATIONS:
                    instruction = ReturnInstruction(op_value, operands, disasm)
                else:
                    instruction = Instruction("None", None, disasm)
                    #print("%d: Instruction-None" % (idx))

                lifted_instructions[idx] = instruction
                idx += instr.get_length()

            '''
            Analysis applied to the block of instructions,
            different data analysis could be applied to lifted
            ninstructions in order to recognize data types,
            instruction types and so on.
            '''
            intent_class_analysis(instr_block, lifted_instructions)

        return lifted_instructions


class Instruction:
    def __init__(self, kind, op_value, disasm):
        self.kind = kind
        self.op_value = op_value
        self.disasm = disasm

        try:
            self.name = DALVIK_INSTRUCTION_NAMES[self.op_value]
        except KeyError:
            # print('Invalid opcode {}'.format(self.op_value))
            self.name = 'INVALID'
            # TODO: do something more here?

    def get_name(self):
        return self.name

    def get_kind(self):
        return self.kind

    def get_op_value(self):
        return self.op_value

    def get_disasm(self):
        return self.disasm

    def _get_types_as_list(self, types_str: str):
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


class UnaryInstruction(Instruction):
    operations = {0x7b: "-", 0x7d: "-", 0x7f: "-", 0x80: "-",
                  0x7c: "~", 0x7e: "~",
                  0x81: "int", 0x84: "int", 0x87: "int", 0x88: "int", 0x8a: "int", 0x8b: "int", 0x8f: "int",
                  0x82: "float", 0x83: "float", 0x85: "float", 0x86: "float", 0x89: "float", 0x8c: "float",
                  0x8d: "chr", 0x8e: "chr"}

    def __init__(self, op_value, operands, disasm, kind):
        self.src_register = operands[0][1]
        self.dst_register = operands[1][1]
        self.operation = self.operations[op_value]
        super(UnaryInstruction, self).__init__(kind, op_value, disasm)

    def get_src_register(self):
        return self.src_register

    def get_dst_register(self):
        return self.dst_register

    def get_full_instruction(self):
        source_reg_type = ""
        if self.op_value in range(0x87, 0x8d):
            source_reg_type = "float"
        else:
            source_reg_type = "int"
        return "%s(%s(registers[%d]))" % (self.operation, source_reg_type, self.src_register)


class BinaryInstruction(Instruction):
    operations = {0x90: "+", 0x9b: "+", 0xd0: "+", 0xd8: "+",
                  0xc6: "+", 0xcb: "+", 0xa6: "+", 0xab: "+",
                  0xb0: "+", 0xbb: "+",
                  0x91: "-", 0x9c: "-", 0xc7: "-", 0xcc: "-",
                  0xa7: "-", 0xac: "-", 0xb1: "-", 0xbc: "-",
                  0x92: "*", 0x9d: "*", 0xd2: "*", 0xda: "*",
                  0xc8: "*", 0xcd: "*", 0xa8: "*", 0xad: "*",
                  0xb2: "*", 0xbd: "*",
                  0x93: "/", 0x9e: "/", 0xd3: "/", 0xdb: "/",
                  0xc9: "/", 0xce: "/", 0xa9: "/", 0xae: "/",
                  0xb3: "/", 0xbe: "/",
                  0x94: "%", 0x9f: "%", 0xd4: "%", 0xdc: "%",
                  0xca: "%", 0xcf: "%", 0xaa: "%", 0xaf: "%",
                  0xb4: "%", 0xbf: "%",
                  0x95: "&", 0xa0: "&", 0xb5: "&", 0xc0: "&",
                  0xd5: "&", 0xdd: "&",
                  0x96: "|", 0xa1: "|", 0xb6: "|", 0xc1: "|",
                  0xd6: "|", 0xde: "|",
                  0x97: "^", 0xa2: "^", 0xb7: "^", 0xc2: "^",
                  0xd7: "^", 0xdf: "^"}

    def __init__(self, op_value, operands, disasm, kind, cast):
        self.dst_register = operands[0][-1]
        self.src_register = operands[1][-1]
        self.operation = self.operations[op_value]
        self.cast = cast

        # Handle /2addr, /lit8 and /lit16 families
        self.is_to_address = (0xb0 <= op_value <= 0xcf)
        self.is_literal = (0xd0 <= op_value <= 0xe2)

        if self.is_literal:
            self.second_src_register = None
            self.value = operands[2][-1]
        elif self.is_to_address:
            self.second_src_register = None
            self.value = None
        else:
            self.second_src_register = operands[2][-1]
            self.value = None

        super(BinaryInstruction, self).__init__(kind, op_value, disasm)

    def get_dst_register(self):
        return self.dst_register

    def get_src_register(self):
        return self.src_register

    def get_second_src_register(self):
        return self.second_src_register

    def get_value(self):
        return self.value

    def get_operation(self):
        return self.operation

    def get_full_instruction(self):
        if self.is_to_address:
            return self.cast + "(registers[" + str(self.src_register) + "] " + self.operation + " registers[" + str(self.dst_register) + "])"
        elif self.is_literal:
            return self.cast + "(registers[" + str(self.src_register) + "])" + self.operation + " " + str(self.value)
        else:
            return self.cast + "(registers[" + str(self.src_register) + "] " + self.operation + " registers[" + str(self.second_src_register) + "])"


class ShiftInstruction(Instruction):
    operations = {0x98: "<<", 0xa3: "<<", 0xe0: "<<", 0xb8: "<<", 0xc3: "<<",
                  0x99: ">>", 0x9a: ">>", 0xa4: ">>", 0xa5: ">>", 0xe1: ">>", 0xe2: ">>",
                  0xb9: ">>", 0xba: ">>", 0xc4: ">>", 0xc5: ">>"}

    def __init__(self, op_value, operands, disasm, kind):
        self.dst_register = operands[0][1]
        self.src_register = operands[1][1]
        self.mask = int(operands[2][-1])
        self.op_type = kind
        self.operation = self.operations[op_value]
        if self.op_type == "Unary":
            super(ShiftInstruction, self).__init__("UnaryShift", op_value, disasm)
        elif self.op_type == "Binary":
            super(ShiftInstruction, self).__init__("BinaryShift", op_value, disasm)

    def get_dst_register(self):
        return self.dst_register

    def get_src_register(self):
        return self.src_register

    def get_mask(self):
        return self.mask

    def get_full_instruction(self):
        if self.op_type == "Unary":
            return "int(registers[" + str(self.src_register) + "])" + self.operation + "(mask & 0x1f)"
        elif self.op_type == "Binary":
            return "int(registers[" + str(self.dst_register) + "]" + self.operation + "(registers[" + str(self.src_register) + "] & 0x1f))"


class CallInstruction(Instruction):
    operations = {0x6e: "call-virtual", 0x6f: "call-super", 0x70: "call-direct", 0x71: "call-static", 0x72: "call-interface",
                  0x74: "call-virtual-range", 0x75: "call-super-range", 0x76: "call-direct-range", 0x77: "call-static-range", 0x78: "call-interface-range"}

    def __init__(self, op_value, operands, disasm, length):
        self.registers = [operands[i][-1] for i in range(0, len(operands)-1)]
        self.length = length
        self.target = operands[-1][-1]
        self.class_name = self.target.split('->')[0]
        self.return_type = self._get_types_as_list(
            self.target.split(')')[1])[0]
        self.parameters_types = self._get_types_as_list(
            self.target[self.target.find('('):self.target.find(')')+1])
        self.method = self.target.split('->')[1].split('(')[0]
        self.descriptor = '(' + self.target.split('(')[1]
        self.operation = self.operations[op_value]
        # WARNING: AF
        # If I'm not mistaken, this are invoke calls and if the
        # result is stored, then there will only be one register
        try:
            self.return_register = self.registers[0]
        except IndexError:
            self.return_register = 0
        self.intent_object = None # intent associated to the call
        if op_value in [0x6e, 0x74]:
            super(CallInstruction, self).__init__("VirtualCall", op_value, disasm)
        elif op_value in [0x6f, 0x75]:
            super(CallInstruction, self).__init__("SuperClassCall", op_value, disasm)
        elif op_value in [0x71, 0x77]:
            super(CallInstruction, self).__init__("StaticCall", op_value, disasm)
        elif op_value in [0x70, 0x76]:
            super(CallInstruction, self).__init__("DirectCall", op_value, disasm)
        elif op_value in [0x72, 0x78]:
            super(CallInstruction, self).__init__("InterfaceCall", op_value, disasm)

    def get_parameters(self):
        return self.registers

    def get_length(self):
        return self.length

    def get_called_target(self):
        return self.target

    def get_method(self):
        return self.method

    def get_class(self):
        return self.class_name

    def get_parameters_types(self):
        return self.parameters_types

    def get_descriptor(self):
        return self.descriptor

    def get_return_type(self):
        return self.return_type

    def set_return_reg(self, reg):
        self.return_register = reg

    def get_return_reg(self):
        return self.return_register

    def get_intent_object(self):
        return self.intent_object

    def get_full_instruction(self):
        return "0"


class ArrayInstruction(Instruction):
    '''
    Represents either a aget or aput instruction

    All of these instructions follow the same format:
        - first register is either the source (for
          aget-*) or destination (for aput-*)
        - second register is the array register
        - third register is the index register
    '''
    operations = {0x44: 'aget',
                  0x45: 'aget-wide',
                  0x46: 'aget-object',
                  0x47: 'aget-boolean',
                  0x48: 'aget-byte',
                  0x49: 'aget-char',
                  0x4a: 'aget-short',
                  0x4b: 'aput',
                  0x4c: 'aput-wide',
                  0x4d: 'aput-object',
                  0x4e: 'aput-boolean',
                  0x4f: 'aput-byte',
                  0x50: 'aput-char',
                  0x51: 'aput-short'}

    def __init__(self, op_value, operands, disasm):
        self.src_or_dst_register = operands[0][1]
        self.array_register = operands[1][1]
        self.index_register = operands[2][1]
        self.operation = self.operations[op_value]
        if 0x44 <= op_value <= 0x4a:
            super(ArrayInstruction, self).__init__('aget', op_value, disasm)
        elif 0x4b <= op_value <= 0x51:
            super(ArrayInstruction, self).__init__('aput', op_value, disasm)

    def get_src_or_dst_register(self):
        return self.src_or_dst_register

    def get_array_register(self):
        return self.array_register

    def get_index_register(self):
        return self.index_register


class AssignmentInstruction(Instruction):
    '''
    Class to represent one kind of assignment
    different assignments can be done, depending
    on the types used, but mostly the destination
    is a register.

    vx = vy
    vx = result
    vx = "string"
    vx = number

    We will handle this, giving different kind of assignments.
    '''
    operations = {
        0x01: 'move',
        0x02: 'move/from16',
        0x03: 'move/16',
        0x04: 'move-wide',
        0x05: 'move-wide/from16',
        0x06: 'move-wide/16',
        0x07: 'move-object',
        0x08: 'move-object/from16',
        0x09: 'move-object/16',
        0x0A: 'move-result',
        0x0B: 'move-result-wide',
        0x0C: 'move-result-object',
        0x0D: 'move-exception',
        0x12: 'const/4',
        0x13: 'const/16',
        0x14: 'const',
        0x15: 'const/high16',
        0x16: 'const-wide/16',
        0x17: 'const-wide/32',
        0x18: 'const-wide',
        0x19: 'const-wide/high16',
        0x1A: 'const-string',
        0x1B: 'const-string/jumbo',
        0x1C: 'const-class',
    }

    def __init__(self, op_value, operands, disasm):
        self.dst_reg = operands[0][1]
        self.src_reg = None
        self.src_str = None
        self.src_literal = None
        self.src_class = None
        self.last_instr = None

        if op_value in MOVE_REG_OPERATIONS:
            self.src_reg = operands[1][1]
            super(AssignmentInstruction, self).__init__(
                "RegAssignment", op_value, disasm)
        elif op_value in MOVE_RESULT_OPERATIONS:
            super(AssignmentInstruction, self).__init__(
                "ResultAssignment", op_value, disasm)
        elif op_value in MOVE_EXCEPTION:
            super(AssignmentInstruction, self).__init__(
                "ExceptionAssignment", op_value, disasm)
        elif op_value in MOVE_LITERAL:
            super(AssignmentInstruction, self).__init__(
                "LiteralAssignment", op_value, disasm)
            if op_value == 0x15:
                self.src_literal = operands[1][-1] << 16
            elif op_value == 0x19:
                self.src_literal = operands[1][-1] << 48
            else:
                self.src_literal = operands[1][-1]
        elif op_value in MOVE_STRING:
            super(AssignmentInstruction, self).__init__(
                "StringAssignment", op_value, disasm)
            self.src_str = operands[1][-1]
        elif op_value in MOVE_CLASS:
            self.src_class = operands[1][-1]
            super(AssignmentInstruction, self).__init__(
                "ClassAssignment", op_value, disasm)

    def get_dst_register(self):
        """
        Return the destination register from the operation.

        :return: int
        """
        return self.dst_reg

    def get_src_register(self):
        """
        Return the source register from the operation,
        use it only in instructions of kind "RegAssignment"

        :return: int
        """
        return self.src_reg

    def get_src_literal(self):
        """
        Return the source literal from the operation,
        use it only in instructions of kind "LiteralAssignment"

        :return: int
        """
        return self.src_literal

    def get_src_string(self):
        """
        Return the source string from the operation,
        use it only in instructions of kind "StringAssignment"

        :return: str
        """
        return self.src_str

    def get_src_class(self):
        """
        Return the class name from the operation,
        use it only in instructions of kind "ClassAssignment"

        :return: str
        """
        return self.src_class

    def get_last_instr(self):
        """
        When the method is a ResultAssingment, we save the last
        instruction
        
        :return: str
        """
        return self.last_instr

    def set_last_instr(self, instr):
        self.last_instr = instr


class FieldInstruction(Instruction):
    '''
    Class to handle fields instructions, either from object instances (iget*
    and iput*) or from static fields (sget* and sput*).
    '''
    operations = {
        0x52: 'iget',
        0x53: 'iget-wide',
        0x54: 'iget-object',
        0x55: 'iget-boolean',
        0x56: 'iget-byte',
        0x57: 'iget-char',
        0x58: 'iget-short',
        0x59: 'iput',
        0x5a: 'iput-wide',
        0x5b: 'iput-object',
        0x5c: 'iput-boolean',
        0x5d: 'iput-byte',
        0x5e: 'iput-char',
        0x5f: 'iput-short',
        0x60: 'sget',
        0x61: 'sget-wide',
        0x62: 'sget-object',
        0x63: 'sget-boolean',
        0x64: 'sget-byte',
        0x65: 'sget-char',
        0x66: 'sget-short',
        0x67: 'sput',
        0x68: 'sput-wide',
        0x69: 'sput-object',
        0x6a: 'sput-boolean',
        0x6b: 'sput-byte',
        0x6c: 'sput-char',
        0x6d: 'sput-short',
    }

    def __init__(self, op_value, operands, disasm):
        self.src_or_dst_register = operands[0][1]
        self.operation = self.operations[op_value]

        # There is no reference to the object for static field operations
        if op_value <= 0x5f:
            self.object_register = operands[1][1]
        else:
            self.object_register = -1

        self.field_class = operands[-1][-1].split('-')[0]
        self.field_name = operands[-1][-1].split('>')[1].split()[0]
        self.field_type = operands[-1][-1].split()[-1]

        if 0x52 <= op_value <= 0x58:
            super(FieldInstruction, self).__init__('iget', op_value, disasm)
        elif 0x59 <= op_value <= 0x5f:
            super(FieldInstruction, self).__init__('iput', op_value, disasm)
        elif 0x60 <= op_value <= 0x66:
            super(FieldInstruction, self).__init__('sget', op_value, disasm)
        elif 0x67 <= op_value <= 0x6d:
            super(FieldInstruction, self).__init__('sput', op_value, disasm)

    def get_src_or_dst_register(self):
        '''
        Get the register of the source (for *put) or the destination (for *get)

        :return: int
        '''
        return self.src_or_dst_register

    def get_object_register(self):
        '''
        Get the register for the object on which the operation is done.

        Note: this returns -1 for sget* and sput* operations, as there is no
        reference to the object for static field operations.

        :return: int
        '''
        return self.object_register

    def get_field_class(self):
        '''
        Return the field class

        :return: string
        '''
        return self.field_class

    def get_field_name(self):
        '''
        Return the field name

        :return: string
        '''
        return self.field_name

    def get_field_type(self):
        '''
        Return the field type

        :return: string
        '''
        return self.field_type


class ReturnInstruction(Instruction):
    '''
    Class to handle return instructions.

    This class is just to handle implicit methods calls (such as in AsyncTasks)
    in the taint engine, so there is not a lot of code.
    '''
    operations = {
        0x0e: 'return-void',
        0x0f: 'return',
        0x10: 'return-wide',
        0x11: 'return-object',
    }

    def __init__(self, op_value, operands, disasm):
        self.disasm = disasm
        if op_value != 0x0e:
            self.return_register = operands[0][-1]
        else:
            self.return_register = -1
        super(ReturnInstruction, self).__init__('return', op_value, disasm)

    def get_return_register(self):
        ''' Returns the register of the object that will be returned, if any '''
        return self.return_register


if __name__ == '__main__':
    instr = Instruction("test", 0x6e)
    print(instr._get_types_as_list("[[I"))
