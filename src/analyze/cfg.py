#!/usr/bin/env python3

from analyze.dom_tree import build_dom_tree
import graphviz
import math
import sys

skip_file = set()

class cfg_builder:
    def __build_dwarf(self, dwarf):
        for filename in dwarf:
            for entry in dwarf[filename]:
                pc = entry['pc']
                if pc not in self.dwarf_index:
                    self.dwarf_index[pc] = []
                entry['filename'] = filename
                self.dwarf_index[pc].append(entry)
    
    def __build_bb_count(self, bb_count):
        self.cmapR = None
        self.norm = None
        self.bb_count = bb_count
        if bb_count is not None:
            import matplotlib.cm
            from matplotlib.colors import Normalize
            self.cmapR = matplotlib.cm.get_cmap('RdYlGn')
            vmin = math.log2(1 + min([bb_count[bb] for bb in bb_count]))
            vmax = math.log2(1 + max([bb_count[bb] for bb in bb_count]))
            self.norm = Normalize(vmin=vmin, vmax=vmax)

    def __init__(self, bb, bb_size, trans_edge, symbol_name, dwarf=None, bb_count=None):
        self.symbol_name = symbol_name
        self.graph = dict()
        self.dwarf_index = dict()
        self.__build_dwarf(dwarf)
        self.__build_bb_count(bb_count)
        self.bb_symbol = bb[symbol_name]['bb']
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
                            dwarf_line, dwarf_col = self.dwarf_index[instr][0]['line'], self.dwarf_index[instr][0]['col']
                            edge_info = str((dwarf_line, dwarf_col))
                            break
                    # Find first instr that has dwarf in v bb
                    if v_bb_addr in bb[symbol_name]['bb']:
                        for instr in bb[symbol_name]['bb'][v_bb_addr]:
                            if instr in self.dwarf_index:
                                if edge_info is None:
                                    edge_info = ""
                                dwarf_line, dwarf_col = self.dwarf_index[instr][0]['line'], self.dwarf_index[instr][0]['col']
                                edge_info += "->" + str((dwarf_line, dwarf_col))
                                break
                    else:
                        # May call outside of this function, skip it for now
                        pass
                    self.graph[u_bb_addr].append((v, edge_info))
        self.scc_path = dict()
        self.in_degree = dict()
        for u in self.graph:
            if u not in self.in_degree:
                self.in_degree[u] = set()
            for v, _ in self.graph[u]:
                if v not in self.in_degree:
                    self.in_degree[v] = set()
                self.in_degree[v].add(u)
        self.dom_path = dict()
        self.dom_tree_size = dict()
        self.bb_size = dict()
        self.__build_dom_tree(bb, bb_size, symbol_name)
        self.__build_scc_tree(self.graph.keys(), None)

    def __build_scc_tree(self, cur_nodes, mask_root):
        scc = dict()
        dfn = dict()
        lowlink = dict()
        stack = []
        onstack = dict()
        lowdepth = dict()
        def __tarjan(u, depth=0):
            dfn[u] = len(dfn)
            lowlink[u] = dfn[u]
            lowdepth[u] = depth
            stack.append(u)
            onstack[u] = True
            if u in self.graph:
                for v, _ in self.graph[u]:
                    if v not in cur_nodes:
                        continue
                    if v == mask_root:
                        continue
                    if v not in dfn:
                        __tarjan(v, depth+1)
                        lowlink[u] = min(lowlink[u], lowlink[v])
                    elif onstack[v]:
                        lowlink[u] = min(lowlink[u], dfn[v])
            if lowlink[u] == dfn[u]:# u is the root of a scc
                scc_nodes = set()
                while True:
                    v = stack.pop()
                    onstack[v] = False
                    scc_nodes.add(v)
                    if v == u:
                        break
                outer_in_degree = dict()
                for v in scc_nodes:
                    if v in self.in_degree:
                        for w in self.in_degree[v]:
                            if w not in scc_nodes:
                                if v not in outer_in_degree:
                                    outer_in_degree[v] = 0
                                outer_in_degree[v] += 1
                scc_root = u
                if len(outer_in_degree) > 0:
                    scc_root = max(outer_in_degree, key=lambda x: self.dom_tree_size[x])
                scc[scc_root] = scc_nodes
                for v in scc_nodes:
                    if v not in self.scc_path:
                        self.scc_path[v] = []
                    self.scc_path[v].append(scc_root)
        # End of __tarjan function
        for u in cur_nodes:
            in_node_in_scc = set()
            if u is not mask_root:
                for v in self.in_degree[u]:
                    if v in cur_nodes:
                        in_node_in_scc.add(v)
            if len(in_node_in_scc) == 0:
                if u not in dfn:
                    __tarjan(u)
        for u in scc:
            if len(scc[u]) > 1:
                self.__build_scc_tree(scc[u], u)

    def __query_node_dwarf(self, bb_addr):
        res_buf = ""
        if bb_addr in self.bb_symbol:
            for each_pc in self.bb_symbol[bb_addr]:
                if each_pc not in self.dwarf_index:
                    continue
                for each_dwarf in self.dwarf_index[each_pc]:
                    filename, line, col = each_dwarf['filename'], each_dwarf['line'], each_dwarf['col']
                    flags = []
                    for key in each_dwarf:
                        if key not in ['filename', 'line', 'col', 'pc']:
                            if each_dwarf[key]:
                                flags += [key]
                    try:
                        with open(filename, 'r') as f:
                            lines = f.readlines()
                            res_buf += f"{hex(each_pc)}:{line}:{col}:{" ".join(flags)}: {lines[line-1].strip()}\\l"
                    except:
                        res_buf += f"{hex(each_pc)}:{line}:{col}:{" ".join(flags)}\\l"
                        if filename not in skip_file:
                            print(f"Failed to open {filename}", file=sys.stderr)
                        skip_file.add(filename)
                        pass
        return res_buf
    
    def __gen_node_color(self, u):
        color = "white"
        if self.bb_count:
            if u in self.bb_count:
                from matplotlib.colors import rgb2hex
                color = rgb2hex(self.cmapR(self.norm(1 + math.log2(self.bb_count[u]))))
        return color
    
    def __gen_node_anno(self, u):
        dom_path_str = str(hex(u))
        if u in self.dom_path:
            dom_path_str = "\n".join([str(hex(p)) for p in self.dom_path[u]])
        bb_count_log_str = f"{math.log2(self.bb_count[u]):.1f}\n\n" if u in self.bb_count else ""
        node_dwarf = self.__query_node_dwarf(u)
        if node_dwarf is None:
            node_dwarf = ""
        return bb_count_log_str + \
               dom_path_str + "\n" + \
               node_dwarf + \
               f"\n{", ".join([hex(x) for x in self.scc_path[u]]) if u in self.scc_path else ""}" + \
               f"\n{self.bb_size[u] if u in self.bb_size else None}" + \
               f"\n{self.dom_tree_size[u] if u in self.dom_tree_size else None}"

    def build_graphviz(self, filename):
        dot = graphviz.Digraph(comment='Control Flow Graph')
        for u in self.graph:
            node_anno = self.__gen_node_anno(u)
            node_color = self.__gen_node_color(u)
            dot.node(str(hex(u)), node_anno, style="filled", fillcolor=node_color)
            for v, edge_info in self.graph[u]:
                edge_anno = str(edge_info) if edge_info else ""
                dot.edge(str(hex(u)), str(hex(v)), edge_anno)
        with open(f"{filename}", 'w') as f:
            f.write(dot.source)

    def __build_dom_tree(self, bb, bb_size, symbol_name):
        # Find entry node
        entry = []
        for u in sorted(self.in_degree):
            if len(self.in_degree[u]) == 0:
                entry.append(u)
                if len(entry) > 1:
                    print(f"Multiple entry nodes: {", ".join([hex(x) for x in entry])}", file=sys.stderr)
        if len(entry) == 0:
            raise Exception("No entry node")
        # trim self.graph with edge info
        trimmed_graph = dict()
        for u in self.graph:
            trimmed_graph[u] = []
            for v, _ in self.graph[u]:
                trimmed_graph[u].append(v)
        if len(entry) > 1:
            for u in entry:
                if u != entry[0]:
                    trimmed_graph[entry[0]].append(u)
        entry = entry[0] # use the first entry node
        self.dom_tree = build_dom_tree(trimmed_graph, entry)
        def dfs_dom_tree(node: dict, u, path: list):
            bb_addr = bb_size.query_bb_addr(bb_size.query_bb_id(u))
            self.bb_size[u] = len(bb[symbol_name]['bb'][bb_addr]) if bb_addr in bb[symbol_name]['bb'] else 1
            self.dom_tree_size[u] = self.bb_size[u]
            self.dom_path[u] = path
            for v in node:
                dfs_dom_tree(node[v], v, path + [v])
                self.dom_tree_size[u] += self.dom_tree_size[v]
        dfs_dom_tree(self.dom_tree[entry], entry, [entry])

    def build_domtree_graphviz(self, filename):
        dot = graphviz.Digraph(comment='Dominance Tree')
        for u in self.graph:
            node_color = self.__gen_node_color(u)
            node_anno = self.__gen_node_anno(u)
            dot.node(str(hex(u)), node_anno, style="filled", fillcolor=node_color)
        def dfs_dom_tree(node: dict, u):
            for v in node:
                dot.edge(str(hex(u)), str(hex(v)))
                dfs_dom_tree(node[v], v)
        entry = list(self.dom_tree.keys())[0]
        dfs_dom_tree(self.dom_tree[entry], entry)
        with open(f"{filename}", 'w') as f:
            f.write(dot.source)

    def build_scctree_graphviz(self, filename):
        dot = graphviz.Digraph(comment='SCC Tree')
        scc_tree = dict() # scc_tree = {u: {v: {w: {} }}} means u -> v -> w
        for u in self.scc_path:
            cur_node = scc_tree
            for each_node in self.scc_path[u]:
                if each_node not in cur_node:
                    cur_node[each_node] = dict()
                cur_node = cur_node[each_node]
        def dfs_scc_tree(node: dict, path: list):
            for v in node:
                v_path = path + [v]
                node_color = self.__gen_node_color(v)
                node_anno = self.__gen_node_anno(v)
                dot.node("-".join(list(map(str, v_path))), node_anno, style="filled", fillcolor=node_color)
                dot.edge("-".join(list(map(str, path))), "-".join(list(map(str, v_path))))
                dfs_scc_tree(node[v], v_path)
        dfs_scc_tree(scc_tree, [])
        with open(f"{filename}", 'w') as f:
            f.write(dot.source)
