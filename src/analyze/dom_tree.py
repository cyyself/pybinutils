#!/usr/bin/env python3

# graph should be {node1: [child1, child2, ...], node2: [child1, child2, ...], ...}
# return domtree {node: {child1, subchild1: {subsubchild1, ...}, ...}, ...}
def build_dom_tree(graph: dict, start):
    revgraph = dict()
    dfn = dict()
    dfnrev = dict()
    up = dict()
    up[start] = start
    def dfs(u):
        dfn[u] = len(dfn)
        dfnrev[dfn[u]] = u
        if u in graph:
            for v in graph[u]:
                if v not in dfn:
                    up[v] = u
                    dfs(v)
    dfs(start)
    # Build reverse graph
    for u in graph:
        for v in graph[u]:
            if v not in revgraph:
                revgraph[v] = []
            revgraph[v].append(u)
    # Build dominator tree
    fa = dict()
    sdom = dict()
    idom = dict()
    minn = dict()
    aux_graph = dict()
    # init
    for u in dfn.keys():
        fa[u] = u
        sdom[u] = u
        idom[u] = u
        minn[u] = u
    def find(x):
        if fa[x] == x:
            return x
        y = fa[x]
        fa[x] = find(y)
        if dfn[sdom[minn[y]]] < dfn[sdom[minn[x]]]:
            minn[x] = minn[y]
        return fa[x]
    for i in range(len(dfn)-1, 0, -1):
        u = dfnrev[i]
        sdomdfn = dfn[u]
        for v in revgraph[u]:
            if v not in dfn:
                continue
            find(v)
            if dfn[v] < dfn[u]:
                sdomdfn = min(sdomdfn, dfn[v])
            else:
                sdomdfn = min(sdomdfn, dfn[sdom[minn[v]]])
        sdom[u] = dfnrev[sdomdfn]
        fa[u] = up[u]
        if sdom[u] not in aux_graph:
            aux_graph[sdom[u]] = []
        aux_graph[sdom[u]].append(u)
        if up[u] in aux_graph:
            for v in aux_graph[up[u]]:
                find(v)
                if sdom[minn[v]] == up[u]:
                    idom[v] = up[u]
                else:
                    idom[v] = minn[v]
            aux_graph.pop(up[u])
    idom[dfnrev[0]] = dfnrev[0]
    for i in range(1, len(dfn)):
        u = dfnrev[i]
        if idom[u] != sdom[u]:
            idom[u] = idom[idom[u]]
    idomrev = dict()
    for node in idom:
        if idom[node] not in idomrev:
            idomrev[idom[node]] = []
        idomrev[idom[node]].append(node)
    dom_tree = {start: dict()}
    def build_tree(tree: dict, u, root):
        if u in idomrev:
            for v in idomrev[u]:
                if v == root:
                    continue
                if v not in tree:
                    tree[v] = dict()
                build_tree(tree[v], v, u)
    build_tree(dom_tree[start], start, start)
    return dom_tree
