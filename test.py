#!/usr/bin/env python3

# Duplicate of __init__.py to make sure we are using the right version of
# Androguard. Without this the CI breaks for some reason.
import sys
import pdb
import configparser


config = configparser.ConfigParser()
config.read('config.ini')

ANDROGUARD_PATH = ''
DEXTRIPADOR_PATH = ''
try:
    ANDROGUARD_PATH = str(config['PATHS']['ANDROGUARD_PATH'])
    DEXTRIPADOR_PATH = str(config['PATHS']['DEXTRIPADOR_PATH'])
except KeyError as exc:
    print('{ERROR} %s' % str(exc))
    sys.exit(1)

sys.path = [ANDROGUARD_PATH] + sys.path
sys.path = [DEXTRIPADOR_PATH] + sys.path
sys.path = ['.'] + sys.path

import unittest
from taint_analyzer import parse_args, main
from taint_engine import Leak

import logging

class TestTaintAnalysis(unittest.TestCase):

    maxDiff = None

    def testLeakPasswordAsyncTask(self):
        arguments = parse_args(["-a", "tests/TaintAnalysisLeakAsyncTask/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks_asynctask.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManagerActivity;->get_password()Ljava/lang/String;"
        # TODO
        source_class = ""
        source_method = ""
        sink = "Landroid/util/Log;->i(Ljava/lang/String; Ljava/lang/String;)I"
        classname = "Lorg/imdea/networks/taintanalysistestleakpassword/MainActivity$LeakPasswordTask;"
        method = "doInBackground"
        offset = 72
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(set(all_leaks), expected)

    def testLeakPasswordAsyncTask2(self):
        arguments = parse_args(["-a", "tests/TaintAnalysisLeakAsyncTask2/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks_asynctask.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManagerActivity;->get_password()Ljava/lang/String;"
        # TODO
        source_class = ""
        source_method = ""
        sink = "Landroid/util/Log;->i(Ljava/lang/String; Ljava/lang/String;)I"
        classname = "Lorg/imdea/networks/taintanalysistestleakpassword/MainActivity$LeakPasswordTask;"
        method = "onPostExecute"
        offset = 8
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(set(all_leaks), expected)

    def testLeakPassword(self):
        arguments = parse_args(["-a", "tests/TaintAnalysisTestLeakPassword/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;->get_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;"
        source_method = "intermediate_fun_0(Ljava/lang/String;)V"
        sink = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;->leak_password(Ljava/lang/String;)V"
        classname = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;"
        method = "intermediate_fun_2"
        offset = 14
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testLeakPasswordMultipleClasses(self):
        arguments = parse_args(["-a", "tests/TaintAnalysisTestLeakPasswordMultipleClasses/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_multiple_class.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;->get_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;"
        source_method = "intermediate_fun_0(Ljava/lang/String;)V"
        sink = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordLeaker;->leak_password(Ljava/lang/String;)V"
        classname = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManager;"
        method = "intermediate_fun_2"
        offset = 14
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testLeakPasswordMultipleClassesWithIntents(self):
        arguments = parse_args(["-a", "tests/TaintAnalysisTestLeakPasswordMultipleClassesWithIntents/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_multiple_class_with_intents.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManagerActivity;->get_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManagerActivity;"
        source_method = "intermediate_fun_0(Ljava/lang/String;)V"
        sink = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordLeakerService;->leak_password(Ljava/lang/String;)V"
        classname = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordLeakerService;"
        method = "onStartCommand"
        offset = 20
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testLeakPasswordPutExtras(self):
        arguments = parse_args(["-a", "tests/TaintAnalysisTestLeakPasswordPutExtras/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_multiple_class_with_intents.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManagerActivity;->get_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordManagerActivity;"
        source_method = "intermediate_fun_0(Ljava/lang/String;)V"
        sink = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordLeakerService;->leak_password(Ljava/lang/String;)V"
        classname = "Lorg/imdea/networks/taintanalysistestleakpassword/PasswordLeakerService;"
        method = "onStartCommand"
        offset = 240
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testExternalMethods(self):
        arguments = parse_args(["-a", "tests/TestExternalMethods/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_external_methods.txt"])
        all_leaks = main(arguments)
        source = "Landroid/telephony/TelephonyManager;->getLine1Number()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/testexternalmethods/MainActivity;"
        source_method = "sendMessage()V"
        sink = "Landroid/util/Log;->e(Ljava/lang/String; Ljava/lang/String;)I"
        classname = "Lorg/imdea/networks/testexternalmethods/SecondActivity;"
        method = "onCreate"
        offset = 66
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testStartActivity(self):
        arguments = parse_args(["-a", "tests/TestStartActivity/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_test_start_activity.txt"])
        all_leaks = main(arguments)
        source = "Lcom/example/startactivity/MainActivity;->get_amazing_password()Ljava/lang/String;"
        source_class = "Lcom/example/startactivity/MainActivity;"
        source_method = "sendMessage()V"
        sink = "Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V"
        classname = "Lcom/example/startactivity/SecondActivity;"
        method = "onCreate"
        offset = 56
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testStartService(self):
        arguments = parse_args(["-a", "tests/TestStartService/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s",
                                "sources_and_sinks/sources_and_sinks_start_service.txt",
                                "--timing"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/teststartservice/MainActivity;->get_amazing_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/teststartservice/MainActivity;"
        source_method = "onCreate(Landroid/os/Bundle;)V"
        sink = "Landroid/util/Log;->e(Ljava/lang/String; Ljava/lang/String;)I"
        classname = "Lorg/imdea/networks/teststartservice/RegularService;"
        method = "leakPassword"
        offset = 4
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testBindService(self):
        arguments = parse_args(["-a", "tests/TestBindService/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_bind_service.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/testbindservice/MainActivity;->get_amazing_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/teststartservice/MainActivity;"
        source_method = "onCreate(Landroid/os/Bundle;)V"
        sink = "Landroid/util/Log;->e(Ljava/lang/String; Ljava/lang/String;)I"
        classname = "Lorg/imdea/networks/testbindservice/RegularService;"
        method = "leakGlobalPassword"
        offset = 8
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testInstruction(self):
        arguments = parse_args(["-a", "tests/TestInstructions/app/build/" +
                                "outputs/apk/debug/app-debug.apk", "-s",
                                "sources_and_sinks/sources_and_sinks_instructions.txt"])
        all_leaks = main(arguments)
        expected = set()
        source_int = "Lorg/imdea/networks/MainActivity;->getIntPassword()I"
        source_float = "Lorg/imdea/networks/MainActivity;->getFloatPassword()F"
        source_short = "Lorg/imdea/networks/MainActivity;->getShortPassword()S"
        source_boolean = "Lorg/imdea/networks/MainActivity;->getBooleanPassword()Z"
        source_long = "Lorg/imdea/networks/MainActivity;->getLongPassword()J"
        source_byte = "Lorg/imdea/networks/MainActivity;->getBytePassword()B"
        source_class = "Lorg/imdea/networks/MainActivity;"
        source_method_arithmetic = "testAritmethicInstructions()V"
        source_method_boolean = "testBooleanInstructions()V"
        sink = "Landroid/util/Log;->i(Ljava/lang/String; Ljava/lang/String;)I"
        arithmethic_methods = ["leakSumInt", "leakSubInt", "leakMulInt", "leakDivInt",
            "leakRemInt", "leakSumFloat", "leakSubFloat", "leakMulFloat",
            "leakDivFloat", "leakRemFloat", "leakSumShort", "leakSubShort",
            "leakMulShort", "leakDivShort", "leakRemShort",]
        boolean_methods = [
            "leakAndBoolean", "leakOrBoolean", "leakXorBoolean",
            "leakAndLong", "leakOrLong", "leakXorLong",
            "leakAndByte", "leakOrByte", "leakXorByte",
            "leakAndShort", "leakOrShort", "leakXorShort",]
        classname = "Lorg/imdea/networks/AritmethicInstructions;"
        for method in arithmethic_methods:
            if "Int" in method:
                leak = Leak(source_int, sink, classname, method, 20)
                leak.source_classname = source_class
                leak.source_method = source_method_arithmetic
                expected.add(leak)
            elif "Float" in method:
                leak = Leak(source_float, sink, classname, method, 20)
                leak.source_classname = source_class
                leak.source_method = source_method_arithmetic
                expected.add(leak)
            elif "Short" in method:
                leak = Leak(source_short, sink, classname, method, 20)
                leak.source_classname = source_class
                leak.source_method = source_method_arithmetic
                expected.add(leak)
        classname = "Lorg/imdea/networks/BooleanInstructions;"
        for method in boolean_methods:
            if "Boolean" in method:
                leak = Leak(source_boolean, sink, classname, method, 16)
                leak.source_classname = source_class
                leak.source_method = source_method_boolean
                expected.add(leak)
            elif "Byte" in method:
                leak = Leak(source_byte, sink, classname, method, 18)
                leak.source_classname = source_class
                leak.source_method = source_method_boolean
                expected.add(leak)
            # TODO: fix issues with long values (cf issue #22)
            # elif "Long" in method:
            #     leak = Leak(source_long, sink, classname, method, 18)
            #     leak.source_classname = source_class
            #     leak.source_method = source_method_boolean
            #     expected.add(leak)
            elif "Short" in method:
                leak = Leak(source_short, sink, classname, method, 18)
                leak.source_classname = source_class
                leak.source_method = source_method_boolean
                expected.add(leak)
        self.assertEqual(all_leaks, expected)

    def testBroadcastReceiver(self):
        arguments = parse_args(["-a", "tests/TestBroadcastReceiver/app/build/" +
                                "outputs/apk/debug/app-debug.apk",
                                "-s", "sources_and_sinks/sources_and_sinks_broadcast_receiver.txt"])
        all_leaks = main(arguments)
        source = "Lorg/imdea/networks/testbroadcastreceiver/MainActivity;->get_amazing_password()Ljava/lang/String;"
        source_class = "Lorg/imdea/networks/testbroadcastreceiver/MainActivity;"
        source_method = "onCreate(Landroid/os/Bundle;)V"
        sink = "Landroid/util/Log;->e(Ljava/lang/String; Ljava/lang/String;)I"
        classname = "Lorg/imdea/networks/testbroadcastreceiver/MyReceiver;"
        method = "onReceive"
        offset = 126
        expected = set()
        leak = Leak(source, sink, classname, method, offset)
        leak.source_classname = source_class
        leak.source_method = source_method
        expected.add(leak)
        self.assertEqual(all_leaks, expected)


if __name__ == "__main__":
    unittest.main()
