#!/usr/bin/env python3

"""
Method to find trails in a directed graph using igraph.

A trail is defined as a walk (i.e., a finite sequence of edges which joins a
sequence of vertices) without repeated edges.

This implementation is based on code by Jorge Martín Pérez who implemented a
similar function for NetworkX [1].

[1]. https://github.com/networkx/networkx/pull/3393
"""

from itertools import groupby
import igraph


def get_all_trails(initial_graph, origin, to=None, cutoff=-1, mode='out'):
    """
    Generate all trails in the directed graph `initial_graph` from `origin` to
    `to`.

    Parameters
    ----------
    initial_graph : an igraph directed graph

    origin : vertex
        The source for the calculated trails

    to : vertex or list of vertices
       A vertex selector describing the destination for the calculated trails.
       This can be a single vertex ID, a list of vertex IDs, a single vertex
       name, a list of vertex names or a `VertexSeq` object. None means all the
       vertices.

    cutoff : integer, optional
        Maximum length of trail that is considered. If negative, trails of all
        lengths are considered.

    mode : string, optional
        The directionality of the trails. "in" means to calculate incoming
        trails, "out" means to calculate outgoing trails, "all" means to
        calculate both ones.

    Returns
    -------
    trail_generator: generator
       A generator that produces lists of trails.  from the given node to every
       other reachable node in the graph in a list. Note that in case of
       mode="in", the vertices in a trail are returned in reversed order!
    """
    if not initial_graph.is_directed:
        raise NotImplementedError('Graph is not directed')

    # This method can be used on a call graph (in which case the nodes will
    # have ClassAnalysis and MethodAnalysis objects) or a CFG (in which case
    # the nodes will have a basic block object). We check here which is which.
    is_call_graph = False
    if 'class_and_method' in initial_graph.vertex_attributes():
        is_call_graph = True

    graph = igraph.Graph(directed=True)
    vertices = dict()

    # Create nodes representing connection links
    for edge in initial_graph.es:
        src, dst = edge.vertex_tuple
        orig_key = (src.index, 'src', src.index)
        dest_key = (dst.index, 'dst', dst.index)

        if orig_key not in vertices:
            orig = graph.add_vertex(left=src.index, node_type='src', init=src.index)
            for attr in src.attributes():
                orig[attr] = src[attr]
            vertices[orig_key] = orig
        else:
            orig = vertices[orig_key]

        if dest_key not in vertices:
            dest = graph.add_vertex(left=dst.index, node_type='dst', init=dst.index)
            for attr in dst.attributes():
                dest[attr] = dst[attr]
            vertices[dest_key] = dest
        else:
            dest = vertices[dest_key]

        graph.add_edges([(orig, dest)])

    exp_nodes = dict()
    for vertex in graph.vs:
        attrs = vertex.attributes()
        n_id = attrs['left']
        if n_id not in exp_nodes:
            exp_nodes[n_id] = {'src': [], 'dst': []}
        exp_nodes[n_id][attrs['node_type']].append(vertex.index)

    # Connect the intra nodes
    for props in exp_nodes.values():
        for dst in props['dst']:
            for src in props['src']:
                graph.add_edges([(dst, src)])

    # Get the possible sources and destinations for expanded version
    if is_call_graph:
        sources = graph.vs.select(node_type_eq='src', calls_source_eq=True)
    else:
        sources = graph.vs.select(node_type_eq='src', basic_block_eq=origin['basic_block'])

    # Get all targets
    if to is not None:
        targets = list()
        if isinstance(to, int):
            to = [to]
        for dst in to:
            if is_call_graph:
                targets = graph.vs.select(node_type_eq='src', class_and_method_eq=dst['class_and_method'])
            else:
                targets = graph.vs.select(basic_block_eq=dst['basic_block'])
    else:
        targets = graph.vs.select(node_type_eq='src')

    # Get the paths in the extended version of the graph
    init_nodes = {origin.index: origin.attributes()['init'] for origin in graph.vs}
    for src in sources:
        for dst in targets:
            for path in graph.get_all_simple_paths(src, dst, 2 * cutoff, mode):
                trail = list(map(lambda n: init_nodes[n], path))
                yield [x[0] for x in groupby(trail)]
