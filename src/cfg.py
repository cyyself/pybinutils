#!/usr/bin/env python3

from dom_tree import build_dom_tree
import graphviz

class cfg_builder:
    def __build_dwarf(self, dwarf):
        for filename in dwarf:
            for entry in dwarf[filename]:
                line, col, pc = entry[0], entry[1], entry[2]
                if pc not in self.dwarf_index:
                    self.dwarf_index[pc] = []
                self.dwarf_index[pc].append((filename, line, col))

    def __init__(self, bb, bb_size, trans_edge, symbol_name, dwarf=None):
        self.symbol_name = symbol_name
        self.graph = dict()
        self.dwarf_index = dict()
        self.__build_dwarf(dwarf)
        all_bb = set(bb[symbol_name]['bb'].keys())
        for u in trans_edge:
            u_bb_addr = bb_size.query_bb_addr(bb_size.query_bb_id(u))
            if u_bb_addr in all_bb:
                for v in trans_edge[u]:
                    v_bb_addr = bb_size.query_bb_addr(bb_size.query_bb_id(v))
                    assert v_bb_addr == v, f"v_bb_addr: {v_bb_addr}, v: {v}"
                    if u_bb_addr not in self.graph:
                        self.graph[u_bb_addr] = []
                    edge_info = None
                    # Find last instr that has dwarf in u bb
                    for instr in reversed(bb[symbol_name]['bb'][u_bb_addr]):
                        if instr in self.dwarf_index:
                            edge_info = str(self.dwarf_index[instr][0][1:])
                            break
                    # Find first instr that has dwarf in v bb
                    if v_bb_addr in bb[symbol_name]['bb']:
                        for instr in bb[symbol_name]['bb'][v_bb_addr]:
                            if instr in self.dwarf_index:
                                if edge_info is None:
                                    edge_info = ""
                                edge_info += "->" + str(self.dwarf_index[instr][0][1:])
                                break
                    else:
                        # May call outside of this function, skip it for now
                        pass
                    self.graph[u_bb_addr].append((v, edge_info))
        self.scc = dict()
        in_degree = dict()
        for u in self.graph:
            if u not in in_degree:
                in_degree[u] = 0
            for v in self.graph[u]:
                if v not in in_degree:
                    in_degree[v] = 0
                in_degree[v] += 1
        for u in in_degree:
            if in_degree[u] == 0:
                self.__tarjan(u, dict(), dict(), [], dict(), dict())
        self.__build_dom_tree()

    def __tarjan(self, u, dfn, lowlink, stack, onstack, lowdepth, depth=0):
        dfn[u] = len(dfn)
        lowlink[u] = dfn[u]
        lowdepth[u] = depth
        stack.append(u)
        onstack[u] = True
        if u in self.graph:
            for v, _ in self.graph[u]:
                if v not in dfn:
                    self.__tarjan(v, dfn, lowlink, stack, onstack, lowdepth, depth+1)
                    lowlink[u] = min(lowlink[u], lowlink[v])
                elif onstack[v]:
                    lowlink[u] = min(lowlink[u], dfn[v])
        if lowlink[u] == dfn[u]:# u is the root of a scc
            while True:
                v = stack.pop()
                onstack[v] = False
                if v not in self.scc:
                    self.scc[v] = []
                self.scc[v].append(u)
                if v == u:
                    break

    def build_graphviz(self, filename):
        dot = graphviz.Digraph(comment='Control Flow Graph')
        for u in self.graph:
            node_anno = str(hex(u))
            if u in self.dom_path:
                node_anno = "\n".join([str(hex(p)) for p in self.dom_path[u]])
            dot.node(str(hex(u)), node_anno)
            for v, edge_info in self.graph[u]:
                edge_anno = str(edge_info) if edge_info else ""
                dot.edge(str(hex(u)), str(hex(v)), edge_anno)
        with open(f"{filename}", 'w') as f:
            f.write(dot.source)

    def __build_dom_tree(self):
        # Find all incoming edges
        in_degree = dict()
        for u in self.graph:
            if u not in in_degree:
                in_degree[u] = 0
            for v, _ in self.graph[u]:
                if v not in in_degree:
                    in_degree[v] = 0
                in_degree[v] += 1
        # Find entry node
        entry = None
        for u in in_degree:
            if in_degree[u] == 0:
                if entry is not None:
                    raise Exception("Multiple entry nodes")
                entry = u
        if entry is None:
            raise Exception("No entry node")
        # trim self.graph with edge info
        trimmed_graph = dict()
        for u in self.graph:
            trimmed_graph[u] = []
            for v, _ in self.graph[u]:
                trimmed_graph[u].append(v)
        self.dom_tree = build_dom_tree(trimmed_graph, entry)
        self.dom_path = dict()
        def dfs_dom_tree(node: dict, u, path: list):
            self.dom_path[u] = path
            for v in node:
                dfs_dom_tree(node[v], v, path + [v])
        dfs_dom_tree(self.dom_tree[entry], entry, [entry])

    def build_domtree_graphviz(self, filename):
        dot = graphviz.Digraph(comment='Dominance Tree')
        for u in self.graph:
            dot.node(str(hex(u)))
        def dfs_dom_tree(node: dict, u):
            for v in node:
                dot.edge(str(hex(u)), str(hex(v)))
                dfs_dom_tree(node[v], v)
        entry = list(self.dom_tree.keys())[0]
        dfs_dom_tree(self.dom_tree[entry], entry)
        with open(f"{filename}", 'w') as f:
            f.write(dot.source)
