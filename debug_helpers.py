#!/usr/bin/env python3

"""
Debug helpers
Some functions that can be useful for debugging. Just import and use.
"""

import igraph
import hashlib
from xml.sax.saxutils import escape
import textwrap

from androguard.core.androconf import color_range
from androguard.core.bytecodes.dvm_types import Kind, Operand


def show_graph(graph, path_to_color=None):
    """
    Display a graph

    :param graph: a igraph.Graph object
    :param path_to_color: a list of edges to color in the graph
    """
    vertex_colors = list()
    labels = list()
    for node in graph.vs:
        if node['is_root'] is not None:
            vertex_colors.append('blue')
        elif node['calls_source'] is not None:
            vertex_colors.append('green')
        else:
            vertex_colors.append('red')

        labels.append(node['class_and_method'][1].name)

    igraph.plot(graph, vertex_color=vertex_colors, vertex_label=labels)


def disas_method(method_obj):
    """
    Dump the DEX code disassembly of a given method

    :param method_obj: a MethodAnalysis object created by Androguard
    """
    for block in method_obj.get_basic_blocks():
        for instruction in block.get_instructions():
            print(instruction.disasm())


def print_cfg_for_method(method_obj, output_file):
    """
    Creates a PNG file with the CFG of a method.

    Based on code from Androguard. Source: https://github.com/androguard/androguard/blob/master/androguard/core/bytecode.py
    
    :param method_obj: a MethodAnalysis object created by Androguard
    :param output_file: path to the PNG to generate
    """
    method2format(output_file, "png", mx=method_obj)


def _get_operand_html(operand, registers_colors, colors):
    """
    Return a HTML representation of the operand.
    The HTML should be compatible with pydot/graphviz to be used
    inside a node label.
    This is solely used in :func:`~androguard.core.bytecodes.method2dot`
    :param operand: tuple containing the operand type and operands
    :param dict register_colors: key: register number, value: register color
    :param dict colors: dictionary containing the register colors
    :returns: HTML code of the operands
    """
    if operand[0] == Operand.REGISTER:
        return '<FONT color="{}">v{}</FONT>'.format(registers_colors[operand[1]], operand[1])

    if operand[0] == Operand.LITERAL:
        return '<FONT color="{}">0x{:x}</FONT>'.format(colors["literal"], operand[1])

    if operand[0] == Operand.RAW:
        wrapped_adjust = '<br />'.join(escape(repr(i)[1:-1]) for i in textwrap.wrap(operand[1], 64))
        return '<FONT color="{}">{}</FONT>'.format(colors["raw"], wrapped_adjust)

    if operand[0] == Operand.OFFSET:
        return '<FONT FACE="Times-Italic" color="{}">@0x{:x}</FONT>'.format(colors["offset"], operand[1])

    if operand[0] & Operand.KIND:
        if operand[0] == (Operand.KIND + Kind.STRING):
            wrapped_adjust = "&quot; &#92;<br />&quot;".join(map(escape, textwrap.wrap(operand[2], 64)))
            return '<FONT color="{}">&quot;{}&quot;</FONT>'.format(colors["string"], wrapped_adjust)

        if operand[0] == (Operand.KIND + Kind.METH):
            return '<FONT color="{}">{}</FONT>'.format(colors["method"], escape(operand[2]))
        if operand[0] == (Operand.KIND + Kind.FIELD):
            return '<FONT color="{}">{}</FONT>'.format(colors["field"], escape(operand[2]))
        if operand[0] == (Operand.KIND + Kind.TYPE):
            return '<FONT color="{}">{}</FONT>'.format(colors["type"], escape(operand[2]))

        return escape(str(operand[2]))

    return escape(str(operand[1]))


def method2dot(mx, colors=None):
    """
    Export analysis method to dot format.
    A control flow graph is created by using the concept of BasicBlocks.
    Each BasicBlock is a sequence of opcode without any jumps or branch.
    :param mx: :class:`~androguard.core.analysis.analysis.MethodAnalysis`
    :param colors: dict of colors to use, if colors is None the default colors are used
    :returns: a string which contains the dot graph
    """

    font_face = "monospace"

    if not colors:
        colors = {
            "true_branch": "green",
            "false_branch": "red",
            "default_branch": "purple",
            "jump_branch": "blue",
            "bg_idx": "lightgray",
            "idx": "blue",
            "bg_start_idx": "yellow",
            "bg_instruction": "lightgray",
            "instruction_name": "black",
            "instructions_operands": "yellow",
            "raw": "red",
            "string": "red",
            "literal": "green",
            "offset": "#4000FF",
            "method": "#DF3A01",
            "field": "#088A08",
            "type": "#0000FF",
            "registers_range": ("#999933", "#6666FF")
        }

    node_tpl = """
    struct_%s [label=<
        <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="3">
            %s
        </TABLE>
    >];
    """
    label_tpl = """
    <TR>
        <TD ALIGN="LEFT" BGCOLOR="%s">
            <FONT FACE="{font_face}" color="%s">%04x</FONT>
        </TD>
        <TD ALIGN="LEFT" BGCOLOR="%s">
            <FONT FACE="{font_face}" color="%s">%s</FONT> %s
        </TD>
    </TR>
    """.format(font_face=font_face)

    link_tpl = '<TR><TD PORT="{}"></TD></TR>\n'

    edges_html = ""
    blocks_html = ""

    method = mx.get_method()

    # This is used as a seed to create unique hashes for the nodes
    sha256 = hashlib.sha256(
        mx.get_method().get_class_name() + mx.get_method().get_name() + mx.get_method().get_descriptor()).digest()

    # Collect all used Registers and create colors
    if method.get_code() and method.get_code().get_registers_size() != 0:
        registers = {i: c for i, c in enumerate(color_range(colors["registers_range"][0], colors["registers_range"][1],
                                                            method.get_code().get_registers_size()))}
    else:
        registers = dict()

    new_links = []

    # Go through all basic blocks and create the CFG
    for basic_block in mx.basic_blocks:
        ins_idx = basic_block.start
        block_id = hashlib.md5(sha256 + basic_block.get_name()).hexdigest()

        content = link_tpl.format('header')

        for instruction in basic_block.get_instructions():
            if instruction.get_op_value() in (0x2b, 0x2c):
                new_links.append((basic_block, ins_idx, instruction.get_ref_off() * 2 + ins_idx))
            elif instruction.get_op_value() == 0x26:
                new_links.append((basic_block, ins_idx, instruction.get_ref_off() * 2 + ins_idx))

            operands = instruction.get_operands(ins_idx)
            output = ", ".join(_get_operand_html(i, registers, colors) for i in operands)

            bg_idx = colors["bg_idx"]
            if ins_idx == 0 and "bg_start_idx" in colors:
                bg_idx = colors["bg_start_idx"]

            content += label_tpl % (
                bg_idx, colors["idx"], ins_idx, colors["bg_instruction"],
                colors["instruction_name"],
                instruction.get_name(), output)

            ins_idx += instruction.get_length()

        # all blocks from one method parsed
        # updating dot HTML content
        content += link_tpl.format('tail')
        blocks_html += node_tpl % (block_id, content)

        # Block edges color treatment (conditional branchs colors)
        val = colors["true_branch"]
        if len(basic_block.childs) > 1:
            val = colors["false_branch"]
        elif len(basic_block.childs) == 1:
            val = colors["jump_branch"]

        values = None
        # The last instruction is important and still set from the loop
        # FIXME: what if there is no instruction in the basic block?
        if instruction.get_op_value() in (0x2b, 0x2c) and len(basic_block.childs) > 1:
            val = colors["default_branch"]
            values = ["default"]
            values.extend(basic_block.get_special_ins(ins_idx - instruction.get_length()).get_values())

        # updating dot edges
        for DVMBasicMethodBlockChild in basic_block.childs:
            label_edge = ""

            if values:
                label_edge = values.pop(0)

            child_id = hashlib.md5(sha256 + DVMBasicMethodBlockChild[-1].get_name()).hexdigest()
            edges_html += "struct_{}:tail -> struct_{}:header  [color=\"{}\", label=\"{}\"];\n".format(block_id,
                                                                                                       child_id, val,
                                                                                                       label_edge)

            # color switch
            if val == colors["false_branch"]:
                val = colors["true_branch"]
            elif val == colors["default_branch"]:
                val = colors["true_branch"]

        exception_analysis = basic_block.get_exception_analysis()
        if exception_analysis:
            for exception_elem in exception_analysis.exceptions:
                exception_block = exception_elem[-1]
                if exception_block:
                    exception_id = hashlib.md5(sha256 + exception_block.get_name()).hexdigest()
                    edges_html += "struct_{}:tail -> struct_{}:header  [color=\"{}\", label=\"{}\"];\n".format(
                        block_id, exception_id, "black", exception_elem[0])

    for link in new_links:
        basic_block = link[0]
        DVMBasicMethodBlockChild = mx.basic_blocks.get_basic_block(link[2])

        if DVMBasicMethodBlockChild:
            block_id = hashlib.md5(sha256 + basic_block.get_name()).hexdigest()
            child_id = hashlib.md5(sha256 + DVMBasicMethodBlockChild.get_name()).hexdigest()

            edges_html += "struct_{}:tail -> struct_{}:header  [color=\"{}\", label=\"data(0x{:x}) to @0x{:x}\", style=\"dashed\"];\n".format(
                block_id, child_id, "yellow", link[1], link[2])

    method_label = method.get_class_name() + "." + method.get_name() + "->" + method.get_descriptor()

    method_information = method.get_information()
    if method_information:
        method_label += "\\nLocal registers v{} ... v{}".format(*method_information["registers"])
        if "params" in method_information:
            for register, rtype in method_information["params"]:
                method_label += "\\nparam v%d = %s" % (register, rtype)
        method_label += "\\nreturn = %s" % (method_information["return"])

    return {'name': method_label, 'nodes': blocks_html, 'edges': edges_html}

def method2format(output, _format="png", mx=None, raw=None):
    """
    Export method structure as a graph to a specific file format using dot from the graphviz package.
    The result is written to the file specified via :code:`output`.
    There are two possibilites to give input for this method:
    1) use :code:`raw` argument and pass a dictionary containing the keys
    :code:`name`, :code:`nodes` and :code:`edges`.
    This can be created using :func:`method2dot`.
    2) give a :class:`~androguard.core.analysis.analysis.MethodAnalysis`.
    This function requires pydot!
    There is a special format :code:`raw` which saves the dot buffer before it
    is handled by pydot.
    :param str output: output filename
    :param str _format: format type (png, jpg ...). Can use all formats which are understood by pydot.
    :param androguard.core.analysis.analysis.MethodAnalysis mx: specify the MethodAnalysis object
    :param dict raw: use directly a dot raw buffer if None
    """
    # pydot is optional!
    import pydot

    if raw:
        data = raw
    else:
        data = method2dot(mx)

    buff = """
    digraph {{
        graph [rankdir=TB]
        node [shape=plaintext]
        subgraph cluster_{clustername}
        {{
            label="{classname}"
            {nodes}
        }}
        {edges}
    }}
    """.format(clustername=hashlib.md5(output.encode("UTF-8")).hexdigest(),
               classname=data['name'],
               nodes=data['nodes'],
               edges=data['edges'],
               )

    # NOTE: In certain cases the graph_from_dot_data function might fail.
    # There is a bug in the code that certain html strings are interpreted as comment
    # and therefore the dot buffer which is passed to graphviz is invalid.
    # We can not really do anything here to prevent this (except for heavily
    # escaping and replacing all characters).
    # We hope, that this issue get's fixed in pydot, so we do not need to patch
    # stuff here.
    # In order to be able to debug the problems better, we will write the dot
    # data here if the format `raw` is requested, instead of creating the graph
    # and then writing the dot data.
    # If you have problems with certain data, export it as dot and then run
    # graphviz manually to see if the problem persists.
    if _format == "raw":
        with open(output, "w") as fp:
            fp.write(buff)
    else:
        d = pydot.graph_from_dot_data(buff)
        if len(d) > 1:
            # Not sure what to do in this case?!
            log.warnig("The graph generated for '{}' has too many subgraphs! "
                       "Only plotting the first one.".format(output))
        for g in d:
            getattr(g, "write_" + _format.lower())(output)
            break
