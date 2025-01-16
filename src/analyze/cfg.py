#!/usr/bin/env python3

from analyze.dom_tree import build_dom_tree
import graphviz
import math

class cfg_builder:
    def __build_dwarf(self, dwarf):
        for filename in dwarf:
            for entry in dwarf[filename]:
                line, col, pc = entry[0], entry[1], entry[2]
                if pc not in self.dwarf_index:
                    self.dwarf_index[pc] = []
                self.dwarf_index[pc].append((filename, line, col))
    
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
        self.scc_belongs = dict()
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
                self.scc_belongs[v] = u
                if v == u:
                    break

    def __query_node_dwarf(self, bb_addr):
        res_buf = ""
        visited = set()
        if bb_addr in self.bb_symbol:
            for each_pc in self.bb_symbol[bb_addr]:
                if each_pc not in self.dwarf_index:
                    continue
                for each_dwarf in self.dwarf_index[each_pc]:
                    if each_dwarf in visited:
                        continue
                    visited.add(each_dwarf)
                    filename, line, col = each_dwarf
                    with open(filename, 'r') as f:
                        lines = f.readlines()
                        res_buf += f"{line}:{col}: {lines[line-1].strip()}\\l"
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
        return bb_count_log_str + dom_path_str + "\n" + node_dwarf + f"\n{hex(self.scc_belongs[u])}"

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
