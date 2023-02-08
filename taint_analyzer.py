#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import pprint
import pickle
import signal
import logging
import zipfile
import tempfile
import argparse
import subprocess
import configparser
import xml.etree.cElementTree as ElementTree

config = configparser.ConfigParser()
config.read('config.ini')

ANDROGUARD_PATH = ''
DEXTRIPADOR_PATH = ''
AXMLDEC_PATH = ''
try:
    ANDROGUARD_PATH = str(config['PATHS']['ANDROGUARD_PATH'])
    DEXTRIPADOR_PATH = str(config['PATHS']['DEXTRIPADOR_PATH'])
    AXMLDEC_PATH = str(config['PATHS']['AXMLDEC_PATH'])
except KeyError as exc:
    print('{ERROR} %s' % str(exc))
    sys.exit(1)

sys.path = [ANDROGUARD_PATH] + sys.path
sys.path = [DEXTRIPADOR_PATH] + sys.path

from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import Analysis, ClassAnalysis
from androguard.core.analysis.analysis import REF_TYPE
from androguard.core.androconf import show_logging

from permissionTracer_api import PermissionTracer, IntentFilterAnalyzer
from sinks_sources_parser import SourceSink, retrieve_sinks_and_sources

from taint_engine import TaintEngine
from instruction import DexLifter
from utils import _ns, is_class_external
from fields import load_fields_per_class
from intent_methods import get_static_intent_filters, get_icc_intents
from handler_methods import get_handlers
from graph_methods import build_call_graph, build_cfg
from igraph_trails import get_all_trails
from default_methods import DEFAULT_METHODS_PER_USAGE, DEFAULT_ENTRYPOINTS
from bound_services import taint_analyze_binder_methods

FIELDS = dict()

# Will be set to true when the timeout is
# reached, which will terminate the execution
HAS_TIMED_OUT = False


def parse_args(args):
    parser = argparse.ArgumentParser(description="Main script to find leaks")
    parser.add_argument("--apk", "-a", required=True, help="Path to the APK file to be analyzed")
    parser.add_argument("--sources-sinks", "-s", required=True, help="Path to the sources and sinks")
    parser.add_argument("--debug", "-d", action="store_true", help="Print debugging statements")
    parser.add_argument("--timing", "-t", action="store_true", help="Print timing statements")
    parser.add_argument("--strings", "-f", help="File with strings to match in permissionTracer StringAnalyzer")
    parser.add_argument("--custom-perms", "-p", action="store_true", help="Only analyze components protected by custom permissions")
    parser.add_argument("--output", "-o", default=sys.stdout, help="Path where to store the analysis report (defauls to stdout)")
    parser.add_argument("--timelimit", "-l", help="Maximum time (in seconds) allowed for the execution (default to None)")
    return parser.parse_args(args)


def get_params_registers(method_obj):
    """ Returns the registers indexes associated with parameters. Ugly hack. """
    # FIXME: unused
    if method_obj.code:
        total_registers = method_obj.code.get_registers_size()
        method_prototype = method_obj.get_descriptor()

        params = method_prototype.split(')')[0][1:].split()

        if 'static' in method_obj.get_access_flags_string():
            first_param_register = total_registers - len(params)
        else:
            first_param_register = total_registers - len(params) - 1

        return ['v{}'.format(i) for i in range(first_param_register, total_registers)]


def androguard_analyze(apk_path, debug):
    """ Safe call to the AnalyzeAPK method from Androguard """
    androguard_apk = None
    androguard_analysis = None

    if debug:
        # Enable log output
        show_logging(level=logging.INFO)
    else:
        show_logging(level=logging.CRITICAL)

    try:
        androguard_apk, classes_dex, androguard_analysis = AnalyzeAPK(apk_path)
    except Exception as exc:
        print(json.dumps({
            "ERROR_TAG": "EXCEPTION",
            "FILE": apk_path,
            "ERROR_MESSAGE": str(exc),
            "EXCEPTION_TYPE": str(type(exc))
        }))
        sys.exit(1)

    return androguard_apk, classes_dex, androguard_analysis


def get_method_analysis_by_name(method_name: str, class_analysis: ClassAnalysis):
    '''
    Method to get first found method by name from a given class
    analysis, as we do not have the descriptor we will use the
    first one we find.

    :param method_name: name of the method to find.
    :param class_analysis: class where to look for the method.
    '''
    for method in class_analysis.get_methods():
        if str(method.name) == method_name:
            return method

    return None


def generate_xrefs_from_intents(intents: dict, intents_targets: dict, analysis: Analysis, debug):
    '''
    Method to generate xrefs for androguard objects given
    a set of intents, we will create the xrefs_from and
    the xrefs_to both for the class analysis and the method
    analysis objects.

    :param intents: dictionary of intents with information about
                    target classes and source from the call.
    :param intents_targets: dictionary of intents sorted by their target
    :param analysis: Androguard analysis object
    :param debug: to print debug messages or not
    '''
    for class_name in intents.keys():
        intent_class_analysis = analysis.get_class_analysis(class_name)

        if intent_class_analysis is None:
            continue

        for method_name in intents[class_name]:

            # class and method analysis where the intent was used
            # from this we will create the xrefs to the method
            # targeted by the intent.
            intent_class_analysis = analysis.get_class_analysis(class_name)

            if intent_class_analysis is None:
                break

            intent_method_analysis = get_method_analysis_by_name(method_name, intent_class_analysis)

            if intent_method_analysis is None:
                continue

            for intent_object in intents[class_name][method_name]:
                if intent_object is None or intent_object.how_used is None:
                    continue

                # Broadcasted intents have no target class, we must instead
                # rely on intent filters, either from the manifest or
                # dynamically registered
                if 'broadcast' in intent_object.how_used.lower():
                    for target_class in intents_targets.keys():
                        # We first check if there is an "onReceive" method in
                        # the target class, and for that we need the Androguard
                        # ClassAnalysis object
                        target_class_analysis = analysis.get_class_analysis('L{};'.format(target_class.replace('.', '/')))
                        if target_class_analysis is None:
                            # Cannot find class analysis object for the target
                            # class, moving on.
                            continue

                        # Look for the onReceive method
                        # TODO: is this the only possible receiving method?
                        target_method_analysis = None
                        for imethod in target_class_analysis.get_methods():
                            if imethod.name == 'onReceive':
                                target_method_analysis = imethod
                                break

                        if target_method_analysis is None:
                            # Cannot get receiving method, moving on
                            continue

                        if (class_name, method_name) in intents_targets[target_class]:
                            # We have the source and the target, we can create
                            # the XREFs now. First those from the classes
                            intent_class_analysis.add_xref_to(REF_TYPE.INVOKE_VIRTUAL,
                                                              target_class_analysis,
                                                              target_method_analysis,
                                                              intent_object.where_used)
                            target_class_analysis.add_xref_from(REF_TYPE.INVOKE_VIRTUAL,
                                                                intent_class_analysis,
                                                                intent_method_analysis,
                                                                intent_object.where_used)

                            # now those from the methods
                            intent_class_analysis.add_method_xref_to(intent_method_analysis,
                                                                     target_class_analysis,
                                                                     target_method_analysis,
                                                                     intent_object.where_used)
                            target_class_analysis.add_method_xref_from(target_method_analysis,
                                                                       intent_class_analysis,
                                                                       intent_method_analysis,
                                                                       intent_object.where_used)

                    continue

                # Explicit intents should have a target package and class
                else:
                    if intent_object.target_class_name == '' and            \
                            intent_object.target_pkg_name == '':
                        continue

                    # get proper names from class and methods
                    if intent_object.target_pkg_name != '':
                        target_class = "L{}/{};".format(intent_object.target_pkg_name.replace('.','/'),
                                                        intent_object.target_class_name)
                    else:
                        target_class = "L{};".format(intent_object.target_class_name.replace('.','/'))

                    # get the target method, given how the intent is used
                    target_methods = list()
                    # TODO: if DEFAULT_METHODS_PER_USAGE is simplified (see TODO at
                    # the top) then simplfy this also
                    for key in DEFAULT_METHODS_PER_USAGE.keys():
                        if intent_object.how_used in key:
                            for item in DEFAULT_METHODS_PER_USAGE[key]:
                                if isinstance(item, list):
                                    for element in item:
                                        target_methods.append(element)
                                else:
                                    target_methods.append(item)
                            break

                    if len(target_methods) == 0:
                        continue

                    # get the class analysis and method analysis to create the xrefs
                    target_class_analysis = analysis.get_class_analysis(target_class)

                    if target_class_analysis is None:
                        continue

                    target_methods_analyses = list()
                    for target_method_name in target_methods:
                        target_method_analysis = get_method_analysis_by_name(target_method_name, target_class_analysis)

                        if target_method_analysis is not None:
                            target_methods_analyses.append(target_method_analysis)

                    for target_method_analysis in target_methods_analyses:
                        # First add XREFs from the classes
                        intent_class_analysis.add_xref_to(REF_TYPE.INVOKE_VIRTUAL,
                                                          target_class_analysis,
                                                          target_method_analysis,
                                                          intent_object.where_used)
                        target_class_analysis.add_xref_from(REF_TYPE.INVOKE_VIRTUAL,
                                                            intent_class_analysis,
                                                            intent_method_analysis,
                                                            intent_object.where_used)

                        # Next add XREFs from the methods
                        intent_class_analysis.add_method_xref_to(intent_method_analysis,
                                                                 target_class_analysis,
                                                                 target_method_analysis,
                                                                 intent_object.where_used)
                        target_class_analysis.add_method_xref_from(target_method_analysis,
                                                                   intent_class_analysis,
                                                                   intent_method_analysis,
                                                                   intent_object.where_used)

                        # In the case of bindService() we must also add xrefs from
                        # the end of onBind() to the block right after the call to
                        # bindService() to allow the detection of the trail
                        if target_method_name == 'onBind':
                            # TODO: I'm keeping the INVOKE_VIRTUAL, not sure if that's right
                            intent_class_analysis.add_xref_from(REF_TYPE.INVOKE_VIRTUAL,
                                                                target_class_analysis,
                                                                target_method_analysis,
                                                                intent_object.where_used)
                            target_class_analysis.add_xref_to(REF_TYPE.INVOKE_VIRTUAL,
                                                              intent_class_analysis,
                                                              intent_method_analysis,
                                                              intent_object.where_used)
                            intent_class_analysis.add_method_xref_from(intent_method_analysis,
                                                                       target_class_analysis,
                                                                       target_method_analysis,
                                                                       intent_object.where_used)
                            target_class_analysis.add_method_xref_to(target_method_analysis,
                                                                     intent_class_analysis,
                                                                     intent_method_analysis,
                                                                     intent_object.where_used)


def generate_xrefs_from_asynctasks(analysis: Analysis, debug=False):
    '''
    Generate xrefs for AsyncTasks.

    Order of methods for AsyncTasks:
            0. execute or executeOnExecutor
            1. onPreExecute
            2. doInBackground
            3. onPostExecute

    Additionally, devs can call publishProgress from the doInBackground method
    to report on the progress of the task (e.g., to update a progress bar on
    the UI). In this case, the method onProgressUpdate will be called.

    :param analysis: Androguard analysis object
    :param debug: print debug messages (default is not to print them)
    '''
    async_classes = dict()
    async_classes_methods = dict()

    # Get all AsyncTasks
    for class_obj in analysis.get_internal_classes():
        if is_class_external(class_obj):
            continue

        if class_obj.extends != 'Landroid/os/AsyncTask;':
            continue

        # Save ClassAnalysis object
        async_classes[class_obj.name] = class_obj

        # Save MethodAnalysis objects from the class
        if class_obj.name not in async_classes_methods:
            async_classes_methods[class_obj.name] = dict()

        for method_obj in class_obj.get_methods():
            # We are not interested in the "bridge" method
            if 'bridge' in method_obj.get_access_flags_string():
                continue

            async_classes_methods[class_obj.name][method_obj.name] = method_obj

    # Link the default methods together for all the AsyncTask classes
    # We first get the start method, which can be either "execute" or
    # "executeOnExecutor". There cannot be both in the same class.
    start_method = None
    for class_obj_name, class_obj in async_classes.items():
        # Check if the class is called with execute or executeOnExecutor
        if 'execute' in async_classes_methods[class_obj_name]:
            start_method = async_classes_methods[class_obj_name]['execute']
        elif 'executeOnExecutor' in async_classes_methods[class_obj_name]:
            start_method = async_classes_methods[class_obj_name]['executeOnExecutor']
        else:
            if debug:
                print('Error: cannot find start function')
            continue

        # Now link the other methods together
        last_method = start_method

        for def_method_name in ['onPreExecute', 'doInBackground', 'onPostExecute']:
            # Check if the method is actually defined for the curren AsyncTask.
            # Only the doInBackground method is mandatory.
            if def_method_name not in async_classes_methods[class_obj_name]:
                # No such method in the class, we ignore it.
                continue

            def_method_obj = async_classes_methods[class_obj_name][def_method_name]

            # Create the XREFs
            # Note that they can be more than one return statement, but all of
            # them should have an XREF to the next method.
            return_offsets = set()

            idx = 0
            for block in last_method.get_basic_blocks():
                for inst in block.get_instructions():
                    # Op codes for return operations
                    if inst.get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                        return_offsets.add(idx)

                    # Increment offset
                    idx += inst.get_length()

            # The execute and executeOnExecutor methods do not have code, but
            # we still need the XREF
            if last_method.name in {'execute', 'executeOnExecutor'}:
                return_offsets.add(0)

            # Create the XREFs
            for offset in return_offsets:
                class_obj.add_method_xref_to(last_method, class_obj, def_method_obj, offset)
                class_obj.add_method_xref_from(def_method_obj, class_obj, last_method, offset)

            last_method = def_method_obj

        # Link the last method back to the method that initially called execute()
        return_offsets = set()
        idx = 0
        for block in last_method.get_basic_blocks():
            for inst in block.get_instructions():
                # Op codes for return operations
                if inst.get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                    return_offsets.add(idx)

                # Increment offset
                idx += inst.get_length()

        for offset in return_offsets:
            class_obj.add_method_xref_to(last_method, class_obj, start_method, -1)
            class_obj.add_method_xref_from(start_method, class_obj, last_method, -1)

        # Last step: check if the doInBackground method ever calls publishProgress
        # If so, we must add a XREF to the onProgressUpdate method and back
        if 'onProgressUpdate' in async_classes_methods[class_obj_name]:
            background_method = async_classes_methods[class_obj_name]['doInBackground']
            progress_method = async_classes_methods[class_obj_name]['onProgressUpdate']

            idx = 0
            for block in background_method.get_basic_blocks():
                for inst in block.get_instructions():
                    # Op codes for invoke-* operations
                    if inst.get_op_value() == 0x72:
                        called_prototype = inst.get_operands()[-1][-1]
                        if called_prototype.endswith('->publishProgress([Ljava/lang/Object;)V'):
                            class_obj.add_method_xref_to(progress_method, class_obj, background_method, idx)
                            class_obj.add_method_xref_from(background_method, class_obj, progress_method, idx)


                    idx += inst.get_length()

            # Add the XREFs back
            idx = 0
            for block in background_method.get_basic_blocks():
                for inst in block.get_instructions():
                    # Op codes for return operations
                    if inst.get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                        class_obj.add_method_xref_to(background_method, class_obj, progress_method, idx)
                        class_obj.add_method_xref_from(progress_method, class_obj, background_method, idx)

                    # Increment offset
                    idx += inst.get_length()

    return


def generate_xrefs_from_handlers(handlers: dict, analysis: Analysis, debug):
    '''
    Method to generate Androguard XREFs from the handlers and their receivers
    that were detected in the code of the app.
    This method add both class and method XREFs.

    The handlers dictionary has the following format:

        {
            sending_class: {
                (sending_method_name, sending_method_descriptor): {
                     (receiver_class, receiver_method, index),
                     (receiver_class, receiver_method, index),
                     ...
                },
                ...
            }
            ...
        }

    :param handlers: dictionary of handlers with their target as a tuple
                     (ClassAnalysis, MethodAnalysis, index)
    :param analysis: Androguard analysis object
    :param debug: to print debug messages or not
    '''

    for sending_class in handlers.keys():
        sending_class_analysis = analysis.get_class_analysis(sending_class)
        if sending_class_analysis is None:
            if debug:
                print("Error: cannot get ClassAnalysis object for {}".format(sending_class))
                continue

        for (sending_method_name, sending_method_descriptor), receivers in handlers[sending_class].items():
            sending_method_analysis =           \
                    analysis.get_method_analysis_by_name(sending_class,
                                                         sending_method_name,
                                                         sending_method_descriptor)
            if sending_class_analysis is None:
                if debug:
                    print("Error: cannot get MethodAnalysis object for {}".format(sending_method_name))
                    continue

            for receiver_class, receiver_method, index in receivers:
                if receiver_class is None or receiver_method is None:
                    continue

                # Adding class XREFs
                sending_class_analysis.add_xref_to(REF_TYPE.INVOKE_VIRTUAL,
                                                   receiver_class,
                                                   receiver_method,
                                                   index)
                receiver_class.add_xref_from(REF_TYPE.INVOKE_VIRTUAL,
                                             sending_class_analysis,
                                             sending_method_analysis,
                                             index)

                # Adding method XREFs
                sending_class_analysis.add_method_xref_to(sending_method_analysis,
                                                          receiver_class,
                                                          receiver_method,
                                                          index)
                receiver_class.add_method_xref_from(receiver_method,
                                                    sending_class_analysis,
                                                    sending_method_analysis,
                                                    index)


def build_sources_and_sinks_call_graph(sources, sinks, methods_to_analyze, analysis, apk, intents_targets, debug, timing):
    '''
    Method to build the different trees from sinks
    to sources following a bottom-up approach (we
    go up in the call-stack from a sink to a possible
    source), from each of these trees we will check
    if a source is in the tree as a leaf, and we will
    create a path between sink and source (sink-source
    bottom-up path), this path can be used for further
    analysis.

    :param sources: the list of all sources to look for in the code
    :param sinks: the list of all potential sinks
    :param methods_to_analyze: set of methods we want to restrict ourselves to
    :param analysis: analysis object from androguard.
    :param apk: apk object from androguard
    :return: list of paths in the call graph per couple (source, sink)
    '''

    global HAS_TIMED_OUT

    # handle all the trees from the sinks
    sink_trees = {}
    # handle all the paths between sinks
    # and sources in the tree.
    paths_sources_sinks = {}

    if len(sources) == 0 or len(sinks) == 0:
        print("Please specify both sources and sinks to apply the analysis")
        return None

    start_time = time.time()

    # Get the call graph for each of the sources, using the XREFs
    for sink in sinks:
        if HAS_TIMED_OUT:
            break

        if debug:
            print('[build_sources_and_sinks_call_graph] Getting call graph for {}->{}{}'.format(sink.class_name,
                                                                                                sink.method_name,
                                                                                                sink.descriptor))

        class_obj = analysis.get_class_analysis(sink.class_name)
        method_obj = analysis.get_method_analysis_by_name(sink.class_name,
                                                          sink.method_name,
                                                          sink.descriptor)

        if class_obj is None or method_obj is None:
            if debug:
                print('Error: cannot find sink {}->{}{}'.format(sink.class_name,
                                                                sink.method_name,
                                                                sink.descriptor))
            continue

        sink_time = time.time()

        tree = build_call_graph(analysis, apk.get_package(), (class_obj, method_obj), intents_targets, methods_to_analyze, debug, timing)
        tree['sink'] = sink

        if tree:
            sink_trees[sink] = tree

        if timing:
            print('[build_sources_and_sinks_call_graph] got call graph, took {} seconds'.format(round(time.time() - sink_time, 2)))
            print('[build_sources_and_sinks_call_graph] {} nodes and {} edges in call graph'.format(len(tree.vs), len(tree.es)))

    if timing:
        print('[build_sources_and_sinks_call_graph] got all call graphs, took {} seconds'.format(round(time.time() - start_time, 2)))

    # Now we check which sources are in a sink tree. For each occurence, we
    # check if it is present in the call graph and, if so, get all the paths
    # from the source to the sink.
    for source in sources:
        if HAS_TIMED_OUT:
            break

        if debug:
            print('[build_sources_and_sinks_call_graph] looking for paths from {}->{}{}'.format(source.class_name,
                                                                                                source.method_name,
                                                                                                source.descriptor))

        method_source = analysis.get_method_analysis_by_name(source.class_name,
                                                             source.method_name,
                                                             source.descriptor)

        if method_source is None:
            if debug:
                print('[build_sources_and_sinks_call_graph] error: cannot find source {}->{}{}'.format(source.class_name,
                                                                                                       source.method_name,
                                                                                                       source.descriptor))
            continue

        # now go through each generated tree to extract paths
        for sink, tree in sink_trees.items():
            if debug:
                print('[build_sources_and_sinks_call_graph] working with sink {}->{}{}'.format(sink.class_name,
                                                                                               sink.method_name,
                                                                                               sink.descriptor))
                print('[build_sources_and_sinks_call_graph] {} nodes and {} edges in call graph'.format(len(tree.vs), len(tree.es)))

            if timing:
                print('[build_sources_and_sinks_call_graph] looking for paths from {}->{}{}'.format(source.class_name,
                                                                                                    source.method_name,
                                                                                                    source.descriptor))

            for iclass_obj, imethod_obj, _ in method_source.get_xref_from():
                if HAS_TIMED_OUT:
                    break

                # Node to look for in the call graph
                xref_node = (iclass_obj, imethod_obj)

                xref_selected_node = tree.vs.select(class_and_method_eq=xref_node)
                if len(xref_selected_node) > 0:
                    if debug or timing:
                        print('[build_sources_and_sinks_call_graph] found source {}->{}{} in call graph'.format(source.class_name,
                                                                                                                source.method_name,
                                                                                                                source.descriptor))
                    head_node = tree.vs.select(is_root_eq=True)

                    if (source, sink) not in paths_sources_sinks.keys():
                        paths_sources_sinks[(source, sink)] = list()

                    for node in head_node:
                        for path in get_all_trails(tree, node, to=xref_selected_node, mode='in'):
                            paths_sources_sinks[(source, sink)].append([tree.vs[_id]['class_and_method'] for _id in path[::-1]])

                    if timing:
                        print('[build_sources_and_sinks_call_graph] found {} paths'.format(len(paths_sources_sinks[(source, sink)])))

    return paths_sources_sinks




def get_method_objs(apk, api_level):
    """ Get methods that use a string with 'logcat' in it """

    with open('perms_per_api_level.pkl', 'rb') as ifile:
        all_aosp_perms = pickle.load(ifile)

    try:
        aosp_perms = set(all_aosp_perms[api_level].keys())
    except KeyError:
        aosp_perms = None

    protected_components = set()
    for item in apk.get_android_manifest_xml().iter():
        if item.tag == 'activity' or item.tag == 'activity-alias':
            item_name = None
            for field, value in item.items():
                if field == _ns('name'):
                    item_name = value
                if field == _ns('permission'):
                    try:
                        if value not in aosp_perms:
                            protected_components.add('L{};'.format(item_name.replace('.', '/')))
                            break
                    except TypeError:
                        continue
        if item.tag == 'service':
            item_name = None
            for field, value in item.items():
                if field == _ns('name'):
                    item_name = value
                if field == _ns('permission'):
                    try:
                        if value not in aosp_perms:
                            protected_components.add('L{};'.format(item_name.replace('.', '/')))
                            break
                    except TypeError:
                        continue
        if item.tag == 'receiver':
            item_name = None
            for field, value in item.items():
                if field == _ns('name'):
                    item_name = value
                if field == _ns('permission'):
                    try:
                        if value not in aosp_perms:
                            protected_components.add('L{};'.format(item_name.replace('.', '/')))
                            break
                    except TypeError:
                        continue
        if item.tag == 'provider':
            item_name = None
            for field, value in item.items():
                if field == _ns('name'):
                    item_name = value
                if field == _ns('permission'):
                    try:
                        if value not in aosp_perms:
                            protected_components.add('L{};'.format(item_name.replace('.', '/')))
                            break
                    except TypeError:
                        continue

    return protected_components


def get_protected_components(path_to_file, all_aosp_perms):
    if not os.path.isfile(path_to_file):
        if args.debug:
            print('APK at %s does not exists' % path_to_file)
        sys.exit()

    # Create a temporary file to extract the binary manifest into
    fman = tempfile.NamedTemporaryFile(dir='/tmp/')

    try:
        apk_zip = zipfile.ZipFile(path_to_file)
    except (zipfile.BadZipFile, UnicodeDecodeError):
        if args.debug:
            print('APK at %s is not a valid ZIP file' % path_to_file)
        sys.exit()

    try:
        raw_man = apk_zip.read('AndroidManifest.xml')
        with tempfile.NamedTemporaryFile(dir='/tmp/', buffering=0) as fman:
            fman.write(raw_man)
            command = '%s %s' % (AXMLDEC_PATH, fman.name)
            output = subprocess.run(command.split(),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=True)
            manifest = output.stdout
    except (zipfile.BadZipFile, KeyError):
        if args.debug:
            print('Cannot extract manifest from APK')
        sys.exit()

    try:
        xml_tree = ElementTree.ElementTree(ElementTree.fromstring(manifest))
    except (ElementTree.ParseError, TypeError):
        if args.debug:
            print('XML is not well-formed')
        sys.exit()

    protected_components = set()
    package_name = None
    for item in xml_tree.iter():
        if item.tag == 'manifest':
            for field, value in item.items():
                if field == 'package':
                    package_name = value
                    break
                if field == _ns('package'):
                    package_name = value
                    break
        if package_name is not None:
            break

    for item in xml_tree.iter():
        name = ''

        if item.tag == 'activity' or item.tag == 'activity-alias':
            for field, value in item.items():
                if field == _ns('name'):
                    if value.startswith('.'):
                        value = '{}{}'.format(package_name, value)
                    elif '.' not in value:
                        value = '{}.{}'.format(package_name, value)
                    name = 'L{};'.format(value.replace('.', '/'))
                if field == _ns('permission'):
                    if value not in all_aosp_perms:
                        protected_components.add((name, item.tag))

        if item.tag == 'service':
            for field, value in item.items():
                if field == _ns('name'):
                    if value.startswith('.'):
                        value = '{}{}'.format(package_name, value)
                    elif '.' not in value:
                        value = '{}.{}'.format(package_name, value)
                    name = 'L{};'.format(value.replace('.', '/'))
                if field == _ns('permission'):
                    if value not in all_aosp_perms:
                        protected_components.add((name, item.tag))

        if item.tag == 'receiver':
            for field, value in item.items():
                if field == _ns('name'):
                    if value.startswith('.'):
                        value = '{}{}'.format(package_name, value)
                    elif '.' not in value:
                        value = '{}.{}'.format(package_name, value)
                    name = 'L{};'.format(value.replace('.', '/'))
                if field == _ns('permission'):
                    if value not in all_aosp_perms:
                        protected_components.add((name, item.tag))

        if item.tag == 'provider':
            for field, value in item.items():
                if field == _ns('name'):
                    if value.startswith('.'):
                        value = '{}{}'.format(package_name, value)
                    elif '.' not in value:
                        value = '{}.{}'.format(package_name, value)
                    name = 'L{};'.format(value.replace('.', '/'))
                if field == _ns('permission'):
                    if value not in all_aosp_perms:
                        protected_components.add((name, item.tag))

    return protected_components


def generate_list_of_entry_points_protos(protected_components):
    """
    In this function we convert the list of protected components into a list of
    prototypes, using the default methods for each component type.

    :param protected_components: a set of tuples with components names and types
    :return: a set of prototypes
    """
    entry_points = set()

    for component_name, component_type in protected_components:
        for entry_point_name, entry_point_proto in DEFAULT_ENTRYPOINTS[component_type]:
            entry_points.add('{}->{}{}'.format(component_name,
                                               entry_point_name,
                                               entry_point_proto))

    return entry_points


def main(args):
    """
    Main method

    :param args: CLI arguments prepared by argparse
    :return call_graph_paths: path in the call graph from entry points to sources
    :return all_leaks: leaks detected via taint analysis
    """
    path_to_file = args.apk
    path_to_sources_and_sinks = args.sources_sinks

    global HAS_TIMED_OUT

    # Dictionary to store all leaks found through taint analysis
    all_leaks = set()

    # Bound services leaks -- storing them apart, as we might
    # want to process those results differently
    bound_services_leaks = dict()

    # We store the paths from any of the app's entry points to any of the
    # source, which would mean the behavior can be triggered by another app
    call_graph_paths = dict()

    # For custom perms, if there is no protected components we can save time
    # and stop right here
    # TODO: do per API level
    all_aosp_perms = set()
    with open('perms_per_api_level.pkl', 'rb') as ifile:
        jdata = pickle.load(ifile)
        for perms in jdata.values():
            for perm in perms:
                all_aosp_perms.add(perm.strip())

    # Main routine
    if args.custom_perms:
        protected_components = get_protected_components(path_to_file,
                                                        all_aosp_perms)
        if not protected_components:
            return call_graph_paths, all_leaks, bound_services_leaks
    else:
        protected_components = set()

    # Convert the list of protected components into a list of prototypes
    # using the list of default methods
    entry_points = generate_list_of_entry_points_protos(protected_components)

    start_time = time.time()
    # Call to Androguard analysis
    apk, classes_dex, analysis = androguard_analyze(path_to_file, args.debug)
    if apk is None or analysis is None:
        print('Error: failed to analyze APK with Androguard')
        # TODO: raise exception here instead
        sys.exit(1)

    if args.timing:
        print('[-] Load APK took {} seconds'.format(round(time.time() - start_time, 2)))

    # Load fields per class
    start_time = time.time()
    # FIELDS = load_fields_per_class(analysis)
    # pprint.pprint(FIELDS["Lcom/asus/soundrecorder/record/RecordController;"])
    # sys.exit()
    try:
        FIELDS = load_fields_per_class(analysis)
    except Exception as exc:
        if args.debug:
            print("[+] Exception while parsing instance fields", exc)
        FIELDS = dict()

    if args.timing:
        print('[-] Load fields took {} seconds'.format(round(time.time() - start_time, 2)))

    intent_filter_analyzer = IntentFilterAnalyzer(analysis, apk, classes_dex)

    sinks, sources = retrieve_sinks_and_sources(path_to_sources_and_sinks)

    # PermissionTracer
    if args.strings is not None:
        perm_tracer = PermissionTracer(apk, classes_dex, analysis, args.strings)
    else:
        perm_tracer = None

    api_level = apk.get_effective_target_sdk_version()
    if api_level > 29:
        if args.debug:
            print("Api level greater than maximum supported (29), using 29 by default")
        api_level = 29
    elif api_level < 16:
        if args.debug:
            print("Api level lower than minimum supported (16), using 16 by default")
        api_level = 16

    analysis.load_specific_api(api_level)
    for method in analysis.map_method_api.keys():
        sources.append(SourceSink(method.split('-')[0],
                                method.split('-')[1],
                                method.split('-')[2]))

    if args.custom_perms:
        methods_to_analyze = get_method_objs(apk, api_level)
    else:
        methods_to_analyze = None

    if len(sources) == 0:
        print('No source to analyze')
        return call_graph_paths, all_leaks, bound_services_leaks

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    # Get intents declared in the app
    start_time = time.time()
    try:
        icc_intents = get_icc_intents(analysis, FIELDS, args.debug, args.timing)
    except Exception as exc:
        if args.debug:
            print("[+] Exception while parsing intents", exc)
        icc_intents = {}

    if args.timing:
        print('[-] Get ICC intent took {} seconds'.format(round(time.time() - start_time, 2)))

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    # Get statically declared intent filters
    start_time = time.time()
    intent_filters, classes_declaring = get_static_intent_filters(apk)
    if args.timing:
        print('[-] Get intent filters took {} seconds'.format(round(time.time() - start_time, 2)))

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    # Inverse dictionary: sort intents by their target
    start_time = time.time()
    intents_targets = dict()
    for class_name, intents_per_method in icc_intents.items():
        for method_name, values in intents_per_method.items():
            for intent in values:
                if intent.how_used is None:
                    # Unused intent, ignoring.
                    continue

                if intent.target_pkg_name != '' and                         \
                        not intent.target_pkg_name.startswith(apk.get_package()):
                    # Inter app communication, not supported for now
                    continue

                key = (class_name, method_name)

                if 'broadcast' in intent.how_used.lower():
                    # Probably a brodcasted intent
                    if intent.action in classes_declaring:
                        for declaring_class in classes_declaring[intent.action]:
                            if declaring_class not in intents_targets:
                                intents_targets[declaring_class] = dict()

                            if key not in intents_targets[declaring_class]:
                                intents_targets[declaring_class][key] = set()

                            intents_targets[declaring_class][key].add(intent)
                    continue

                # At this point remaining intents are for inter-components
                # communication, so we can ignore the ones for which we are
                # missing an explicit target
                if intent.target_class_name == '':
                    continue

                if not intent.target_class_name.startswith(intent.target_pkg_name):
                    target_class_name = '{}.{}'.format(intent.target_pkg_name,
                                                    intent.target_class_name)
                else:
                    target_class_name = intent.target_class_name

                if target_class_name not in intents_targets:
                    intents_targets[target_class_name] = dict()

                if key not in intents_targets[target_class_name]:
                    intents_targets[target_class_name][key] = set()

                intents_targets[target_class_name][key].add(intent)
    if args.timing:
        print('[-] Sort intents took {} seconds'.format(round(time.time() - start_time, 2)))

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    # Get handlers declared in the app and their targets
    start_time = time.time()
    try:
        handlers = get_handlers(analysis, FIELDS, args.debug, args.timing)
    except Exception as exc:
        if args.debug:
            print("[+] Exception while parsing handlers", exc)
        handlers = {}

    if args.timing:
        print('[-] Get handlers took {} seconds'.format(round(time.time() - start_time, 2)))

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    # Create androguard xrefs
    start_time = time.time()
    generate_xrefs_from_intents(icc_intents, intents_targets, analysis, args.debug)
    if args.timing:
        print('[-] XREFs from intents took {} seconds'.format(round(time.time() - start_time, 2)))

    start_time = time.time()
    generate_xrefs_from_asynctasks(analysis, args.debug)
    if args.timing:
        print('[-] XREFs from AsyncTasks took {} seconds'.format(round(time.time() - start_time, 2)))

    start_time = time.time()
    generate_xrefs_from_handlers(handlers, analysis, args.debug)
    if args.timing:
        print('[-] XREFs from handlers took {} seconds'.format(round(time.time() - start_time, 2)))

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    taint_engine = TaintEngine(analysis, sources, sinks, intents_targets, args.debug)
    bound_services_leaks = taint_analyze_binder_methods(apk, analysis, FIELDS, taint_engine)

    if HAS_TIMED_OUT:
        return call_graph_paths, all_leaks, bound_services_leaks

    # Load sources and sinks
    start_time = time.time()
    sources_sinks_graph = build_sources_and_sinks_call_graph(sources,
                                                            sinks,
                                                            methods_to_analyze,
                                                            analysis,
                                                            apk,
                                                            intents_targets,
                                                            args.debug,
                                                            args.timing)
    if args.timing:
        print('[-] build call graph took {} seconds'.format(round(time.time() - start_time, 2)))

    if sources_sinks_graph is None:
        return call_graph_paths, all_leaks, bound_services_leaks

    for source_sink, paths in sources_sinks_graph.items():
        if HAS_TIMED_OUT:
            return call_graph_paths, all_leaks, bound_services_leaks

        source = source_sink[0]
        sink = source_sink[1]
        if sink not in call_graph_paths:
            call_graph_paths[sink] = set()

        for path_idx, path in enumerate(paths):
            if HAS_TIMED_OUT:
                return call_graph_paths, all_leaks, bound_services_leaks

            first_method = path[0][1]
            first_method_is_external = first_method.is_external()
            first_method_proto = '{}->{}({}'.format(first_method.full_name.split()[0],
                                                    first_method.full_name.split()[1],
                                                    first_method.full_name.split('(')[1])

            last_method = path[-1][1]
            last_method_is_external = last_method.is_external()
            last_method_proto = '{}->{}({}'.format(last_method.full_name.split()[0],
                                                last_method.full_name.split()[1],
                                                last_method.full_name.split('(')[1])
            last_but_one_method = path[-2][1]

            if args.timing:
                print('---------- [{}] -> [{}] (call graph path #{})'
                        .format(first_method_proto, last_method_proto, path_idx))

            if args.custom_perms:
                # In custom perms mode we only process a path if it is linked
                # to a component protected by a custom permission

                if first_method_proto not in entry_points          \
                        and last_method_proto not in entry_points:
                    if args.debug:
                        print('  [-] Not linked to protected component, ignoring')
                    continue

            start_time = time.time()
            cfg = build_cfg(analysis, path, intents_targets, args.debug)
            if args.timing:
                print('  [-] build CFG took {} seconds'.format(round(time.time() - start_time, 2)))
                print('  [-] {} nodes and {} edges in CFG'.format(len(cfg.vs), len(cfg.es)))

            start_time = time.time()

            if args.custom_perms:
                if first_method_proto in entry_points:
                    # Converting to tuple, as list are not hashable
                    call_graph_paths[sink].add(tuple(path))

            # We first get the basic blocks in which the source method is called
            source_blocks = set()
            source_blocks.add(first_method.get_basic_blocks()[0])

            sink_blocks = set()
            if last_method_is_external:
                # The last method is external, so we do not have access to its
                # basic blocks. Instead, we look for calls to this method in
                # the last but one function in the call graph
                for block in last_but_one_method.get_basic_blocks():
                    for inst in block.get_instructions():
                        # Check for invoke-* calls
                        if inst.get_op_value() in {0x6e, 0x6f, 0x70, 0x71, 0x72,
                                                0x74, 0x75, 0x76, 0x77, 0x78}:
                            prototype = inst.get_operands()[-1][-1]
                            if '{}->{}{}'.format(sink.class_name,
                                                sink.method_name,
                                                sink.descriptor) == prototype:
                                # We found a call!
                                sink_blocks.add(block)
                                continue
            else:
                # The last method is not external, so we do have access to its
                # basic blocks. In this case we get all the blocks that end
                # with a return instruction
                for block in last_method.get_basic_blocks():
                    if block.get_last().get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                        # Block is an end block
                        sink_blocks.add(block)
            if args.timing:
                print('  [-] get sources and sinks blocks took {} seconds'.format(round(time.time() - start_time, 2)))


            if len(source_blocks) == 0:
                print('No source')
                continue

            if len(sink_blocks) == 0:
                print('No sink')
                continue

            start_time = time.time()
            for root in source_blocks:
                if HAS_TIMED_OUT:
                    return call_graph_paths, all_leaks, bound_services_leaks

                root_node = cfg.vs.select(basic_block_eq=root)[0]
                # print(len(sink_blocks))
                leaf_nodes = [cfg.vs.select(basic_block_eq=leaf)[0] for leaf in sink_blocks]
                # for cfg_path in all_trails(cfg, source=root, target=leaf):
                # paths = list(get_all_trails(cfg, root_node, to=leaf_nodes))
                paths = list(cfg.get_all_simple_paths(root_node, to=leaf_nodes))
                if args.timing:
                    print('  [-] {} paths to analyze'.format(len(paths)))
                for cfg_path in paths:
                    if args.debug:
                        print('===== start path =====')

                    # show_graph(cfg, path_to_color=[item for item in zip(cfg_path[:-1], cfg_path[1:])])
                    # Instance of DEXLifter
                    dex_lifter = DexLifter()

                    # Instance of TaintEngine
                    taint_engine = TaintEngine(analysis, [source], [sink], intents_targets, args.debug)

                    # Get blocks per method
                    methods = list()
                    blocks_per_method = dict()
                    blocks_in_order = list()
                    for block_id in cfg_path:
                        block = cfg.vs[block_id]['basic_block']
                        blocks_in_order.append((block.get_method(), block))

                    blocks_to_lift = list()
                    # Get the first method
                    last_method = blocks_in_order[0][0]
                    for method, block in blocks_in_order:
                        if method == last_method:
                            blocks_to_lift.append(block)
                            continue

                        if args.debug:
                            print('--- lift method {} ---'.format(last_method.name))
                        next_method_proto = '{}->{}{}'.format(method.full_name.split()[0],
                                                            method.full_name.split()[1],
                                                            method.full_name.split()[2])
                        lifted_instructions = dex_lifter.lift_method_blocks(blocks_to_lift)
                        new_leaks = taint_engine.apply_taint_block(lifted_instructions,
                                                                analysis.get_method(last_method),
                                                                args.debug,
                                                                next_method_proto)
                        for leak in new_leaks:
                            leak.source_classname = str(first_method.full_name.split()[0])
                            leak.source_method = str('{}{}'.format(first_method.full_name.split()[1],
                                                                first_method.full_name.split()[2]))
                            formatted_path = ['{}->{}{}'.format(item[0].name,
                                                                item[1].name,
                                                                item[1].descriptor) for item in path]
                            leak.path = formatted_path
                            # print(leak.toJSON())
                            all_leaks.add(leak)

                        # Reset variables
                        last_method = method
                        blocks_to_lift = [block]

                    if args.debug:
                        print('--- lift method {} ---'.format(last_method.name))
                    next_method_proto = '{}->{}{}'.format(method.full_name.split()[0],
                                                        method.full_name.split()[1],
                                                        method.full_name.split()[2])
                    lifted_instructions = dex_lifter.lift_method_blocks(blocks_to_lift)
                    new_leaks = taint_engine.apply_taint_block(lifted_instructions,
                                                            analysis.get_method(last_method),
                                                            args.debug,
                                                            next_method_proto)
                    for leak in new_leaks:
                        leak.source_classname = str(first_method.full_name.split()[0])
                        leak.source_method = str('{}{}'.format(first_method.full_name.split()[1],
                                                            first_method.full_name.split()[2]))
                        formatted_path = ['{}->{}{}'.format(item[0].name,
                                                            item[1].name,
                                                            item[1].descriptor) for item in path]
                        leak.path = formatted_path
                        # print(leak.toJSON())
                        all_leaks.add(leak)
            if args.timing:
                print('  [-] tainting paths took {} seconds'.format(round(time.time() - start_time, 2)))

    if HAS_TIMED_OUT:
        if args.debug:
            print("Time out signal received")
    return call_graph_paths, all_leaks, bound_services_leaks


def signal_handler(signum, frame):
    global HAS_TIMED_OUT
    HAS_TIMED_OUT = True


if __name__ == '__main__':
    start_time = time.time()

    # User input
    # Get arguments, we send the list of arguments to the function
    # to make it easier to include args in tests
    args = parse_args(sys.argv[1:])

    if args.timelimit is not None:
        timelimit = int(args.timelimit)
        if timelimit <= 0:
            if args.debug:
                print("Invalid time limit: must be strictly positive")
                print("Ignoring time limit for this execution")
        else:
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(timelimit)

    call_graph_paths, all_leaks, bound_services_leaks = main(args)

    # Disable the alarm now that we are out of the main function
    signal.alarm(0)

    formatted_paths = dict()
    for source, paths in call_graph_paths.items():
        formatted_paths[str(source)] = list()
        for path in paths:
            formatted_paths[str(source)].append(['{}->{}({}'.format(item[1].full_name.split()[0],
                                                                    item[1].full_name.split()[1],
                                                                    item[1].full_name.split('(')[1]) for item in path])

    formatted_bound_services_leaks = dict()
    for method, leaks in bound_services_leaks.items():
        formatted_bound_services_leaks[str(method)] = list()
        for leak in bound_services_leaks[method]:
            formatted_bound_services_leaks[str(method)].append(leak.toJSON())

    report = {
        'leaks': [leak.to_dict() for leak in all_leaks],
        'call_graph_paths' : formatted_paths,
        'bound_services_leaks' : formatted_bound_services_leaks,
        'elapsed_time': time.time() - start_time,
        'has_reached_timeout': HAS_TIMED_OUT,
    }

    if isinstance(args.output, str):
        with open(args.output, 'w') as ofile:
            json.dump(report, ofile, sort_keys=True)
    else:
        pprint.pprint(report)
