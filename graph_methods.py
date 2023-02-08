#!/usr/bin/env python3

import igraph
from utils import is_class_external
from default_methods import DEFAULT_METHODS, DEFAULT_METHODS_PER_USAGE

def build_cfg_for_method(method_analysis_obj, debug=False):
    """
    Build the CFG of the given method. We need to build the CFG to accurately
    extract intents and their attributes.

    :param method_analysis_obj: MethodAnalysis object from Androguard
    :param debug: print debug messages (defaults to False)
    :return: a NetworkX directed graph object
    """
    # Get all the basic blocks from the method
    blocks = list(method_analysis_obj.get_basic_blocks())

    # Create the NetworkX directed graph object
    # cfg = nx.DiGraph()
    cfg = igraph.Graph(directed=True)

    # Add the first basic block as root of the graph
    root = blocks.pop(0)
    root_node = cfg.add_vertex(basic_block=root, is_root=True)

    # Create stack for CFG creation loop
    # stack = [root]
    stack = [root_node]
    processed_blocks = set()

    # Loop until the stack is empty
    while stack:
        # current_block = stack.pop(0)
        current_node = stack.pop(0)

        # Add all children to the CFG
        # for child in current_block.childs:
        for child in current_node['basic_block'].childs:
            # `child' is a tuple, the basic block object is actually in the
            # last position
            child_block = child[-1]

            # Adding node and edge to the CFG
            # Note: we do not care about the edge object, so we use add_edges()
            # instead of add_edge() to save the creation overhead
            # cfg.add_node(child_block)
            # cfg.add_edge(current_block, child_block)
            child_node = cfg.add_vertex(basic_block=child_block, is_root=False)
            cfg.add_edges([(current_node, child_node)])

            # Adding the child to the stack
            # if child_block not in processed_nodes:
            #     stack.append(child_block)
            if child_node['basic_block'] not in processed_blocks:
                stack.append(child_node)

        # processed_nodes.add(current_block)
        processed_blocks.add(current_node['basic_block'])

    return cfg


def build_call_graph(analysis, pkg_name, obj, intents, methods_to_analyze, debug, timing):
    """
    Build the call graph, rooted at the specified source (obj)

    :param analysis: Androguard analysis object
    :param pkg_name: the package name of the application
    :param obj: the source, as a tuple (ClassAnalysis, MethodAnalysis)
    :param intents: dictionary of ICC intents found in the app
    :param debug: boolean, print debug messages or not
    :param timing: boolean, print timing messages or not
    :return: the call graph, a igraph directed graph
    """

    call_graph = igraph.Graph(directed=True)

    root = obj
    root_node = call_graph.add_vertex(class_and_method=root, is_root=True)

    stack = [root_node]

    # We need to keep track of the nodes and edges we add to the graph to avoid
    # duplicates
    vertex_ids = dict()
    vertex_tuples = set()

    # Adding root node to vertex_ids
    vertex_ids[root] = root_node.index

    # The first node is the source: we need to mark the methods that call it
    current_node_is_root = True

    # Building the tree
    while stack:
        current_node = stack.pop(0)
        current_node_id = vertex_ids[current_node['class_and_method']]
        class_obj, method_obj = current_node['class_and_method']

        # Get internal XREFs from MethodAnalysis object
        xrefs = set()
        for iclass, imethod, _ in method_obj.get_xref_from():
            if is_class_external(iclass):
                continue

            # if methods_to_analyze is not None and current_node_is_root and iclass.name not in methods_to_analyze:
            #     continue

            xrefs.add((iclass, imethod, 'from'))

        for iclass, imethod, _ in method_obj.get_xref_to():
            if is_class_external(iclass):
                continue
            xrefs.add((iclass, imethod, 'to'))

        # Convert to a list to maintain a consistent order across executions
        xrefs = list(xrefs)

        # Add XREFs to the call graph
        for xref_class_obj, xref_method_obj, direction in xrefs:
            value = (xref_class_obj, xref_method_obj)
            new_node = False

            xref_nodes = call_graph.vs.select(class_and_method_eq=value)
            if len(xref_nodes) == 0:
                new_node = True
                added_node = call_graph.add_vertex(class_and_method=value)
                if current_node_is_root and direction == 'from':
                    added_node['calls_source'] = True
                vertex_ids[value] = added_node.index
                xref_nodes = [added_node]

            for xref_node in xref_nodes:
                xref_node_id = vertex_ids[xref_node['class_and_method']]
                if direction == 'from':
                    edge = (xref_node_id, current_node_id)
                elif direction == 'to':
                    edge = (current_node_id, xref_node_id)

                if edge not in vertex_tuples:
                    call_graph.add_edges([edge])
                    vertex_tuples.add(edge)

                if xref_node in set(stack) or not new_node:
                    continue

                stack.append(xref_node)

        # We check if the current method is a potential "receiver".
        # No need to go further if the method is not a potential receiver.
        if str(method_obj.name) not in DEFAULT_METHODS:
            if current_node_is_root:
                current_node_is_root = False
            continue

        # Get intents in current method
        target_class = class_obj.name[1:-1].replace('/', '.')
        try:
            intents_targetting_current_class = intents[target_class]
            if timing:
                print('[build_call_graph] potential receiver: {} intents for {}'.format(len(intents_targetting_current_class), target_class))

            for key, _ in intents_targetting_current_class.items():
                # Getting class and method names
                sending_class, sending_method = key

                # Getting ClassAnalysis object
                sending_class_obj = analysis.get_class_analysis(sending_class)
                if sending_class_obj is None:
                    # Cannot find class in the app
                    continue

                # Getting MethodAnalysis object
                sending_method_obj = None
                for method in sending_class_obj.get_methods():
                    if method.name == sending_method:
                        sending_method_obj = method
                        break

                if sending_method_obj is None:
                    # Cannot find method in the class
                    continue

                # Value to be stored in the call graph
                sending_value = (sending_class_obj, sending_method_obj)

                if sending_value not in vertex_ids:
                    sending_node = call_graph.add_vertex(class_and_method=sending_value)
                    if current_node_is_root:
                        sending_node['calls_source'] = True
                    vertex_ids[sending_value] = sending_node.index
                    sending_node_id = sending_node.index
                    stack.append(sending_node)
                else:
                    sending_node_id = vertex_ids[sending_value]

                edge = (sending_node_id, current_node_id)
                if edge not in vertex_tuples:
                    call_graph.add_edges([edge])
                    vertex_tuples.add(edge)

        except KeyError:
            if current_node_is_root:
                current_node_is_root = False
            continue

        if current_node_is_root:
            current_node_is_root = False

    return call_graph


def build_cfg(analysis, path, intents_targets, debug):
    """
    Build the CFG following a call path

    :param analysis: Androguard Analysis object
    :param path: the path across the call graph
    :param debug: print debug messages or not
    """
    # TODO: for some reasons there are some isolated blocks (i.e., no next or
    # prev). Investigate if that is a bug in Androguard or something normal.

    path_cfgs = list()

    vertex_ids = dict()
    vertex_tuples = set()

    for class_obj, method_obj in path:
        if len(list(method_obj.get_basic_blocks())) == 0:
            # Some functions (such as the execute function for AsyncTasks) do
            # not have any code, so no basic blocks either. We create an empty
            # one to prevent crashes.
            dummy_block = DVMBasicBlock(0, None, method_obj.method, None)
            method_obj.basic_blocks.push(dummy_block)

        basic_blocks = list(method_obj.get_basic_blocks())
        # cfg = nx.DiGraph(class_obj=class_obj, method_obj=method_obj)
        cfg = igraph.Graph(directed=True)
        cfg['class_obj'] = class_obj
        cfg['method_obj'] = method_obj

        # Add all nodes to the graph
        for idx, basic_block in enumerate(basic_blocks):
            if basic_block not in vertex_ids:
                if idx > 0:
                    added_node = cfg.add_vertex(basic_block=basic_block)
                else:
                    added_node = cfg.add_vertex(basic_block=basic_block, is_root=True)
                vertex_ids[basic_block] = added_node.index

        # Add all edges between nodes
        for node in cfg.vs:
            basic_block = node['basic_block']
            for next_block in basic_block.get_next():
                block_node = cfg.vs.select(basic_block_eq=next_block[-1])[0]
                if (node, block_node) not in vertex_tuples:
                    cfg.add_edges([(node, block_node)])
                    vertex_tuples.add((node, block_node))

        # Save CFG
        path_cfgs.append(cfg)

    # We now loop over the CFG and merge them into a big one
    inter_cfg = igraph.Graph(directed=True)
    vertex_ids = dict()
    vertex_tuples = set()
    for cfg in path_cfgs:
        for node in cfg.vs:
            is_node_root = node['is_root'] is not None
            added_node = inter_cfg.add_vertex(basic_block=node['basic_block'], is_root=is_node_root)
            vertex_ids[node['basic_block']] = added_node.index
        for edge in cfg.es:
            source, target = edge.vertex_tuple
            source_node = inter_cfg.vs.select(basic_block_eq=source['basic_block'])[0]
            target_node = inter_cfg.vs.select(basic_block_eq=target['basic_block'])[0]
            if (source_node, target_node) not in vertex_tuples:
                inter_cfg.add_edges([(source_node, target_node)])
                vertex_tuples.add((source_node, target_node))

    for idx, cfg in enumerate(path_cfgs):
        current_class = cfg['class_obj']
        current_method = cfg['method_obj']

        try:
            next_cfg = path_cfgs[idx + 1]
        except IndexError:
            if debug:
                print('end of path')
            # End of path
            # TODO: should we do something here?
            continue

        next_class = next_cfg['class_obj']
        next_method = next_cfg['method_obj']

        # We need to select in the inter-CFG do get the correct node IDs
        _root = next_cfg.vs.select(is_root_eq=True)[0]
        next_cfg_root = inter_cfg.vs.select(basic_block_eq=_root['basic_block'])[0]

        current_proto = '{}->{}{}'.format(current_class.name, current_method.name, current_method.descriptor)
        next_proto = '{}->{}{}'.format(next_class.name, next_method.name, next_method.descriptor)

        # if next_method.is_external() and                \
        #         next_class.extends != 'Landroid/os/AsyncTask;':
        #     continue

        # Check if the next method is a potential receiver
        launchers = list()
        is_launcher = False
        class_name = next_class.name[1:-1].replace('/', '.')
        if class_name in intents_targets:
            key = (current_class.name, current_method.name)
            if key in intents_targets[class_name]:
                # We have the parsed intents from the current class to the next
                # one. We use that to know how the next class is launched.
                is_launcher = True
                launchers = [(item.how_used, item.where_used) for item in intents_targets[class_name][key]]

        for xref in next_method.get_xref_from():
            if xref[0].name == current_class.name and \
                    xref[1].name == current_method.name:
                if current_class.extends == 'Landroid/os/AsyncTask;' and        \
                        current_method.name in {'execute', 'executeOnExecutor'}:
                    # These methods have no block
                    continue

                # Found the next call. Now we need to find the right block to
                # link based on the offset
                for block in current_method.get_basic_blocks():
                    # TODO: double check this
                    idx = block.start
                    for inst in block.get_instructions():

                        if inst.get_op_value() in {0x6e, 0x6f, 0x70, 0x71, 0x72,
                                                   0x74, 0x75, 0x76, 0x77, 0x78}:
                            prototype = inst.get_operands()[-1][-1]
                            if is_launcher:
                                proto_method_name = prototype.split('>')[1].split('(')[0]
                                if (proto_method_name, idx) in launchers:
                                    # Check if the next method in the call
                                    # graph is the method expected by the
                                    # launcher
                                    got_match = False
                                    for item in DEFAULT_METHODS_PER_USAGE[prototype.split('>')[1]]:
                                        if isinstance(item, list):
                                            if next_method.name in item:
                                                got_match = True
                                                break
                                        elif isinstance(item, str):
                                            if next_method.name == item:
                                                got_match = True
                                                break

                                    if got_match:
                                        block_node = inter_cfg.vs.select(basic_block_eq=block)[0]
                                        if (block_node, next_cfg_root) not in vertex_tuples:
                                            inter_cfg.add_edges([(block_node, next_cfg_root)])
                                            vertex_tuples.add((block_node, next_cfg_root))
                                        idx += inst.get_length()
                                        continue

                            if prototype == next_proto:
                                block_node = inter_cfg.vs.select(basic_block_eq=block)[0]
                                if (block_node, next_cfg_root) not in vertex_tuples:
                                    inter_cfg.add_edges([(block_node, next_cfg_root)])
                                    vertex_tuples.add((block_node, next_cfg_root))

                        idx += inst.get_length()

        if current_class.extends == 'Landroid/app/Service;'         \
                and current_method.name == 'onBind':
            # Here we must link the end of the onBind() method (which returns the
            # binder object) to the basic block right after the call to onBind()

            # We first get the block after the call to onBind(). To do this we
            # parse the next method until we find the call.
            target_block = None
            found_target = False
            for block in next_method.get_basic_blocks():
                if found_target:
                    target_block = block
                    break

                for inst in block.get_instructions():
                    if inst.get_op_value() in {0x6e, 0x6f, 0x70, 0x71, 0x72,
                                                0x74, 0x75, 0x76, 0x77, 0x78}:
                        prototype = inst.get_operands()[-1][-1]
                        if prototype == '{}->bindService(Landroid/content/Intent; Landroid/content/ServiceConnection; I)Z'.format(next_class.name):
                            found_target = True
                            break

            if target_block is None:
                continue

            target_block_node = inter_cfg.vs.select(basic_block_eq=target_block)[0]

            added_edge = False
            for block in current_method.get_basic_blocks():
                for inst in block.get_instructions():
                    if inst.get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                        block_node = inter_cfg.vs.select(basic_block_eq=block)[0]
                        if (block_node, target_block_node) not in vertex_tuples:
                            inter_cfg.add_edges([(block_node, target_block_node)])
                            vertex_tuples.add((block_node, target_block_node))
                        added_edge = True
                if added_edge:
                    break

        # AsyncTask do not explicitely call their next default method, so we
        # have to artificially add edges
        if current_class.extends == 'Landroid/os/AsyncTask;':
            # Not interested in the bridge method
            if 'bridge' in current_method.get_access_flags_string():
                continue

            # We link the last block of the current method to the first block
            # of the next method.
            # if len(current_method.get_basic_blocks()) == 0:
            #     # The execute function doesn't have any code, so no basic
            #     # blocks either. We create an empty one to prevent crashes.
            #     dummy_block = DVMBasicBlock(0, None, current_method.method, None)
            #     current_method.basic_blocks.push(dummy_block)

            got_return_block = False
            for block in current_method.get_basic_blocks():
                try:
                    for inst in block.get_instructions():
                        # Op codes for return operations
                        if inst.get_op_value() in {0x0e, 0x0f, 0x10, 0x11}:
                            node_block = inter_cfg.vs.select(basic_block_eq=block)[0]
                            got_return_block = True
                            break
                    if got_return_block:
                        break
                except AttributeError:
                    # TODO: here we assume that the method just has a dummy
                    # block, something that we should explicitely check.
                    node_block = block

            try:
                if (node_block, next_cfg_root) not in vertex_tuples:
                    inter_cfg.add_edges([(node_block, next_cfg_root)])
                    vertex_tuples.add((node_block, next_cfg_root))
            except TypeError:
                # TODO: just a temporary fix, will probably break the CFG
                continue

    return inter_cfg
