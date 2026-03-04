#!/usr/bin/env python3
"""Parse Fortran source via flang parse-tree into a structured Python dict.

Produces a clang-JSON-like AST representation from
``flang-new -fc1 -fdebug-dump-parse-tree-no-sema`` output, with each
statement and construct annotated with ``range.begin`` / ``range.end``
(1-based line:col) resolved by keyword-scanning the original source in
source order.

Only SPEC CPU 2006/2017 Fortran patterns are tested, so some corner cases may not be handled

Written by Claude Opus 4.6.

Public API
----------
parse_fortran_ast(source_file, flags=None, comp_dir=None, flang='flang-new')
    → nested dict with 'kind', 'inner', optional 'value'/'name', and 'range'.

extract_loop_regions(ast_dict)
    → list of (begin_line, begin_col, end_line, end_col) for DO loops.

extract_syntax_flags(flags)
    → list of flags suitable for syntax-only AST parsing.

parse_fortran_do_loops(source_file)
    → list of (begin_line, begin_col, end_line, end_col) via regex fallback.

get_loop_regions(source_file, flags=None, comp_dir=None)
    → list of (begin_line, begin_col, end_line, end_col); tries AST first,
      falls back to regex-based DO/END DO parsing.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_fortran_ast(
    source_file: str,
    flags: Optional[List[str]] = None,
    comp_dir: Optional[str] = None,
    flang: str = 'flang-new',
    resolve_tokens: bool = False,
) -> Optional[Dict[str, Any]]:
    """Parse a Fortran source file and return a structural AST dict.

    Parameters
    ----------
    source_file : str
        Path to the Fortran source file.
    flags : list[str] | None
        Extra compile flags (e.g. ``['-I', '/path']``).
    comp_dir : str | None
        Working directory for the flang invocation.
    flang : str
        Path to the *flang-new* binary.
    resolve_tokens : bool
        If *True*, also resolve leaf-token positions (Name, literals)
        within each statement's source range.  Slower but gives finer
        granularity.  Default *False* (statement / construct level only).

    Returns
    -------
    dict | None
        Nested AST dict, or *None* on failure.
    """
    ext = os.path.splitext(source_file)[1].lower()
    is_fixed = ext in ('.f', '.f77', '.fpp', '.for', '.ftn')

    cmd: List[str] = [flang, '-fc1', '-fdebug-dump-parse-tree-no-sema']
    if is_fixed:
        cmd.append('-ffixed-form')
    if flags:
        cmd.extend(flags)
    cmd.append(source_file)

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, cwd=comp_dir,
        )
        if r.returncode != 0 or not r.stdout:
            return None
    except Exception:
        return None

    tree = _parse_tree_text(r.stdout)
    if tree is None:
        return None

    try:
        with open(source_file, 'r', errors='replace') as fh:
            source_lines = fh.readlines()
    except Exception:
        return tree     # return structural tree without locations

    _resolve_locations(tree, source_lines, is_fixed,
                       resolve_tokens=resolve_tokens)
    return tree


def extract_loop_regions(
    ast: Dict[str, Any],
) -> List[Tuple[int, int, int, int]]:
    """Walk a parsed AST and return DO-loop regions.

    Returns
    -------
    list of (begin_line, begin_col, end_line, end_col)
    """
    loops: List[Tuple[int, int, int, int]] = []

    def _walk(node: Dict[str, Any]) -> None:
        kind = node.get('kind', '')
        # DoConstruct (structured END DO loops)
        if kind == 'DoConstruct' and 'range' in node:
            r = node['range']
            loops.append((
                r['begin']['line'], r['begin']['col'],
                r['end']['line'], r['end']['col'],
            ))
        # LabelDoStmt (old-style labeled DO loops — no DoConstruct wrapper)
        elif kind == 'LabelDoStmt' and 'range' in node:
            r = node['range']
            loops.append((
                r['begin']['line'], r['begin']['col'],
                r['end']['line'], r['end']['col'],
            ))
        for child in node.get('inner', []):
            _walk(child)

    _walk(ast)
    return loops


# ---------------------------------------------------------------------------
# 1. Parse the indented tree text into a nested dict
# ---------------------------------------------------------------------------

def _parse_tree_text(text: str) -> Optional[Dict[str, Any]]:
    """Parse ``flang -fdebug-dump-parse-tree`` output into a nested dict."""
    raw_lines = text.split('\n')

    # Skip header "===== Flang: parse tree dump ====="
    start = 0
    for i, ln in enumerate(raw_lines):
        if ln.startswith('='):
            start = i + 1
        else:
            break
    raw_lines = raw_lines[start:]

    parsed: List[Tuple[int, List[Tuple[str, Optional[str]]]]] = []
    for ln in raw_lines:
        depth, chain = _parse_line(ln)
        if chain:
            parsed.append((depth, chain))
    if not parsed:
        return None
    return _build_tree(parsed)


def _parse_line(line: str) -> Tuple[int, List[Tuple[str, Optional[str]]]]:
    """Return ``(depth, [(name, value|None), ...])`` for one tree line."""
    depth = 0
    i = 0
    while i + 1 < len(line) and line[i] == '|' and line[i + 1] == ' ':
        depth += 1
        i += 2

    content = line[i:].rstrip()
    # A trailing ' ->' (or ' -> ') means empty continuation — strip it
    # so that 'EndDoStmt -> ' becomes just 'EndDoStmt'.
    if content.endswith('->'):
        content = content[:-2].rstrip()
    content = content.strip()
    if not content:
        return depth, []

    parts = content.split(' -> ')
    chain: List[Tuple[str, Optional[str]]] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        eq = re.match(r'^([A-Za-z_][A-Za-z_0-9:]*)\s*=\s*(.*)', part)
        if eq:
            name = eq.group(1)
            value = eq.group(2).strip()
            if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
                value = value[1:-1]
            chain.append((name, value))
        else:
            chain.append((part, None))
    return depth, chain


def _build_tree(
    parsed: List[Tuple[int, List[Tuple[str, Optional[str]]]]],
) -> Dict[str, Any]:
    idx = [0]

    def _make_node(chain: List[Tuple[str, Optional[str]]],
                   sub: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a (possibly chained) node from *chain* with *sub* children."""
        name, val = chain[-1]
        node: Dict[str, Any] = {'kind': name, 'inner': sub}
        if val is not None:
            node['value'] = val
        for j in range(len(chain) - 2, -1, -1):
            n2, v2 = chain[j]
            wrapper: Dict[str, Any] = {'kind': n2, 'inner': [node]}
            if v2 is not None:
                wrapper['value'] = v2
            node = wrapper
        return node

    def _children(parent_depth: int) -> List[Dict[str, Any]]:
        children: List[Dict[str, Any]] = []
        while idx[0] < len(parsed):
            depth, chain = parsed[idx[0]]
            if depth <= parent_depth:
                break
            if depth != parent_depth + 1:
                idx[0] += 1
                continue
            idx[0] += 1
            if not chain:
                continue
            sub = _children(depth)
            children.append(_make_node(chain, sub))
        return children

    # Find the minimum depth — normally 0 for top-level "Program -> ..." lines.
    min_depth = min(d for d, _ in parsed)

    # Collect ALL root-level entries (files with multiple program units
    # produce multiple "Program -> ProgramUnit -> ..." at the same depth).
    roots: List[Dict[str, Any]] = []
    while idx[0] < len(parsed):
        depth, chain = parsed[idx[0]]
        if depth != min_depth:
            idx[0] += 1
            continue
        idx[0] += 1
        if not chain:
            continue
        sub = _children(min_depth)
        roots.append(_make_node(chain, sub))

    if len(roots) == 1:
        return roots[0]
    # Wrap multiple program units in a TranslationUnit node
    return {'kind': 'TranslationUnit', 'inner': roots}


# ---------------------------------------------------------------------------
# 2. Resolve source locations by keyword-scanning
# ---------------------------------------------------------------------------

# Map statement kind → regex keyword (case-insensitive).
# None means "handle specially" (AssignmentStmt, TypeDeclarationStmt …).
_STMT_KW: Dict[str, Optional[str]] = {
    # --- program units ---
    'ModuleStmt':               r'\bMODULE\b',
    'EndModuleStmt':            r'\bEND\s+MODULE\b|\bEND\s*$',
    'SubmoduleStmt':            r'\bSUBMODULE\b',
    'EndSubmoduleStmt':         r'\bEND\s+SUBMODULE\b|\bEND\s*$',
    'ProgramStmt':              r'\bPROGRAM\b',
    'EndProgramStmt':           r'\bEND\s+PROGRAM\b|\bEND\s*$',
    'SubroutineStmt':           r'\bSUBROUTINE\b',
    'EndSubroutineStmt':        r'\bEND\s+SUBROUTINE\b|\bEND\s*$',
    'FunctionStmt':             r'\bFUNCTION\b',
    'EndFunctionStmt':          r'\bEND\s+FUNCTION\b|\bEND\s*$',
    'BlockDataStmt':            r'\bBLOCK\s*DATA\b',
    'EndBlockDataStmt':         r'\bEND\s+BLOCK\s*DATA\b|\bEND\s*$',
    # --- DO ---
    'NonLabelDoStmt':           r'\bDO\b',
    'LabelDoStmt':              r'\bDO\b',
    'EndDoStmt':                r'\bEND\s*DO\b',
    # --- IF ---
    'IfThenStmt':               r'\bIF\s*\(',
    'ElseIfStmt':               r'\bELSE\s*IF\b',
    'ElseStmt':                 r'\bELSE\b',
    'EndIfStmt':                r'\bEND\s*IF\b',
    'IfStmt':                   r'\bIF\s*\(',
    # --- SELECT ---
    'SelectCaseStmt':           r'\bSELECT\s*CASE\b',
    'SelectRankStmt':           r'\bSELECT\s*RANK\b',
    'SelectTypeStmt':           r'\bSELECT\s*TYPE\b',
    'CaseStmt':                 r'\bCASE\b',
    'TypeGuardStmt':            r'\bTYPE\s+IS\b|\bCLASS\s+IS\b|\bCLASS\s+DEFAULT\b',
    'EndSelectStmt':            r'\bEND\s*SELECT\b',
    # --- WHERE ---
    'WhereConstructStmt':       r'\bWHERE\s*\(',
    'MaskedElsewhereStmt':      r'\bELSE\s*WHERE\b',
    'ElsewhereStmt':            r'\bELSE\s*WHERE\b',
    'EndWhereStmt':             r'\bEND\s*WHERE\b',
    'WhereStmt':                r'\bWHERE\s*\(',
    # --- FORALL ---
    'ForallConstructStmt':      r'\bFORALL\b',
    'EndForallStmt':            r'\bEND\s*FORALL\b',
    'ForallStmt':               r'\bFORALL\b',
    # --- ASSOCIATE / BLOCK / CRITICAL ---
    'AssociateStmt':            r'\bASSOCIATE\b',
    'EndAssociateStmt':         r'\bEND\s*ASSOCIATE\b',
    'BlockStmt':                r'\bBLOCK\b',
    'EndBlockStmt':             r'\bEND\s*BLOCK\b',
    'CriticalStmt':             r'\bCRITICAL\b',
    'EndCriticalStmt':          r'\bEND\s*CRITICAL\b',
    'ChangeTeamStmt':           r'\bCHANGE\s+TEAM\b',
    'EndChangeTeamStmt':        r'\bEND\s+TEAM\b',
    # --- specification ---
    'ContainsStmt':             r'\bCONTAINS\b',
    'ImplicitStmt':             r'\bIMPLICIT\b',
    'UseStmt':                  r'\bUSE\b',
    'ImportStmt':               r'\bIMPORT\b',
    'ParameterStmt':            r'\bPARAMETER\b',
    'SaveStmt':                 r'\bSAVE\b',
    'CommonStmt':               r'\bCOMMON\b',
    'EquivalenceStmt':          r'\bEQUIVALENCE\b',
    'NamelistStmt':             r'\bNAMELIST\b',
    'DimensionStmt':            r'\bDIMENSION\b',
    'ExternalStmt':             r'\bEXTERNAL\b',
    'IntrinsicStmt':            r'\bINTRINSIC\b',
    'IntentStmt':               r'\bINTENT\b',
    'OptionalStmt':             r'\bOPTIONAL\b',
    'ValueStmt':                r'\bVALUE\b',
    'VolatileStmt':             r'\bVOLATILE\b',
    'AsynchronousStmt':         r'\bASYNCHRONOUS\b',
    'TargetStmt':               r'\bTARGET\b',
    'PointerStmt':              r'\bPOINTER\b',
    'ProtectedStmt':            r'\bPROTECTED\b',
    'AllocatableStmt':          r'\bALLOCATABLE\b',
    'BindStmt':                 r'\bBIND\b',
    'DataStmt':                 r'\bDATA\b',
    'FormatStmt':               r'\bFORMAT\b',
    'EntryStmt':                r'\bENTRY\b',
    'StmtFunctionStmt':         None,  # looks like assignment
    # --- interface / type ---
    'InterfaceStmt':            r'\bINTERFACE\b|(?:ABSTRACT\s+INTERFACE)',
    'EndInterfaceStmt':         r'\bEND\s*INTERFACE\b',
    'DerivedTypeStmt':          r'\bTYPE\b',
    'EndTypeStmt':              r'\bEND\s*TYPE\b',
    'TypeBoundProcedureStmt':   r'\bPROCEDURE\b',
    'FinalProcedureStmt':       r'\bFINAL\b',
    'GenericStmt':              r'\bGENERIC\b',
    'PrivateStmt':              r'\bPRIVATE\b',
    'SequenceStmt':             r'\bSEQUENCE\b',
    'ComponentDefStmt':         None,
    # --- enum ---
    'EnumDefStmt':              r'\bENUM\b',
    'EndEnumStmt':              r'\bEND\s*ENUM\b',
    'EnumeratorDefStmt':        r'\bENUMERATOR\b',
    # --- executable ---
    'CallStmt':                 r'\bCALL\b',
    'ReturnStmt':               r'\bRETURN\b',
    'CycleStmt':                r'\bCYCLE\b',
    'ExitStmt':                 r'\bEXIT\b',
    'GotoStmt':                 r'\bGO\s*TO\b',
    'ComputedGotoStmt':         r'\bGO\s*TO\b',
    'ArithmeticIfStmt':         r'\bIF\s*\(',
    'StopStmt':                 r'\bSTOP\b',
    'ErrorStopStmt':            r'\bERROR\s+STOP\b',
    'ContinueStmt':             r'\bCONTINUE\b',
    'AllocateStmt':             r'\bALLOCATE\s*\(',
    'DeallocateStmt':           r'\bDEALLOCATE\b',
    'NullifyStmt':              r'\bNULLIFY\b',
    'AssignmentStmt':           None,  # handled specially
    'PointerAssignmentStmt':    None,  # handled specially
    # --- I/O ---
    'WriteStmt':                r'\bWRITE\b',
    'ReadStmt':                 r'\bREAD\b',
    'PrintStmt':                r'\bPRINT\b',
    'OpenStmt':                 r'\bOPEN\b',
    'CloseStmt':                r'\bCLOSE\b',
    'InquireStmt':              r'\bINQUIRE\b',
    'RewindStmt':               r'\bREWIND\b',
    'BackspaceStmt':            r'\bBACKSPACE\b',
    'EndfileStmt':              r'\bENDFILE\b|END\s+FILE',
    'FlushStmt':                r'\bFLUSH\b',
    'WaitStmt':                 r'\bWAIT\b',
}

_TYPE_DECL_RE = re.compile(
    r'\b(?:INTEGER|REAL|DOUBLE\s*PRECISION|COMPLEX|CHARACTER|LOGICAL'
    r'|TYPE|CLASS)\b',
    re.IGNORECASE,
)


def _resolve_locations(
    tree: Dict[str, Any],
    source_lines: List[str],
    is_fixed: bool,
    resolve_tokens: bool = False,
) -> None:
    """Walk *tree* depth-first and add ``range`` dicts."""
    code_info = _preprocess_source(source_lines, is_fixed)
    cursor = [0]           # current source line index (0-based)
    all_stmts: List[Dict[str, Any]] = []  # for LabelDoStmt fixup

    def _first_name(node: Dict[str, Any]) -> Optional[str]:
        if node.get('kind') == 'Name' and 'value' in node:
            return node['value']
        for c in node.get('inner', []):
            n = _first_name(c)
            if n:
                return n
        return None

    def _variable_name(node: Dict[str, Any]) -> Optional[str]:
        for c in node.get('inner', []):
            if c.get('kind') == 'Variable':
                return _first_name(c)
        return _first_name(node)

    def _label_value(node: Dict[str, Any]) -> Optional[str]:
        """Extract label from a LabelDoStmt (uint64_t child)."""
        for c in node.get('inner', []):
            if c.get('kind') == 'uint64_t' and 'value' in c:
                return c['value']
        return None

    def _keyword_for(node: Dict[str, Any]) -> Optional[str]:
        kind = node['kind']
        if kind in _STMT_KW:
            pat = _STMT_KW[kind]
            # None means "explicitly unmatchable" — don't use generic
            # fallback, just return None.
            return pat
        if kind == 'TypeDeclarationStmt':
            return _TYPE_DECL_RE.pattern
        if kind in ('AssignmentStmt', 'PointerAssignmentStmt',
                     'StmtFunctionStmt', 'ComponentDefStmt'):
            vn = _variable_name(node)
            if vn:
                return r'(?:^\s*(?:\d+\s+)?)' + re.escape(vn) + r'\s*[=(]'
        # Generic fallback: derive keyword from kind name
        # e.g. "FooBarStmt" → "FOOBAR" — unlikely to match but worth trying
        if kind.endswith('Stmt'):
            kw = kind[:-4]
            # split camelCase
            words = re.findall(r'[A-Z][a-z]*', kw)
            if words:
                return r'\b' + r'\s*'.join(words) + r'\b'
        return None

    _pat_cache: Dict[str, 're.Pattern[str]'] = {}
    # Pre-build index of code lines for fast iteration
    code_line_indices = [i for i, ci in enumerate(code_info) if ci['is_code']]
    import bisect
    MAX_SEARCH_CODE_LINES = 500  # max code lines to scan per search

    def _search(
        pattern: Optional[str], start_line: int,
    ) -> Optional[Tuple[int, int, int]]:
        """Return ``(line_idx, match_start_col, match_end_col)`` 0-based."""
        if pattern is None:
            return None
        pat = _pat_cache.get(pattern)
        if pat is None:
            pat = re.compile(pattern, re.IGNORECASE)
            _pat_cache[pattern] = pat
        pos = bisect.bisect_left(code_line_indices, start_line)
        end_pos = min(pos + MAX_SEARCH_CODE_LINES, len(code_line_indices))
        for idx in range(pos, end_pos):
            li = code_line_indices[idx]
            m = pat.search(code_info[li]['code'])
            if m:
                return (li, m.start(), m.end())
        return None

    def _stmt_end(line_idx: int) -> Tuple[int, int]:
        """Find end of a logical statement (last continuation line).

        Returns ``(end_line_idx, end_col)`` 0-based.
        """
        end = line_idx
        while end + 1 < len(source_lines):
            nxt = end + 1
            if nxt >= len(code_info):
                break
            if not code_info[nxt]['is_code']:
                # blank / comment between continuations — peek ahead
                nxt2 = nxt + 1
                while nxt2 < len(code_info) and not code_info[nxt2]['is_code']:
                    nxt2 += 1
                if nxt2 < len(code_info) and is_fixed:
                    raw = source_lines[nxt2]
                    if len(raw) > 5 and raw[5] not in (' ', '\t', '\n', '\r', ''):
                        end = nxt2
                        continue
                break
            if is_fixed:
                raw = source_lines[nxt]
                if len(raw) > 5 and raw[5] not in (' ', '\t', '\n', '\r', ''):
                    end = nxt
                    continue
            else:
                prev_code = code_info[end]['code'].rstrip()
                this_stripped = source_lines[nxt].lstrip()
                if prev_code.endswith('&') or this_stripped.startswith('&'):
                    end = nxt
                    continue
            break
        ec = len(source_lines[end].rstrip('\n\r'))
        return (end, max(ec, 1))

    def _resolve(node: Dict[str, Any]) -> None:
        kind = node['kind']
        is_stmt = kind.endswith('Stmt')

        if is_stmt:
            pat = _keyword_for(node)
            hit = _search(pat, cursor[0])
            if hit:
                li, cs, _ = hit
                # begin = first non-blank col of the line
                raw = source_lines[li].rstrip('\n\r')
                first_nb = len(raw) - len(raw.lstrip())
                el, ec = _stmt_end(li)
                node['range'] = {
                    'begin': {'line': li + 1, 'col': first_nb + 1},
                    'end':   {'line': el + 1, 'col': ec},
                }
                cursor[0] = li + 1
                all_stmts.append(node)
                # recurse (tokens inside the stmt)
                if resolve_tokens:
                    for c in node.get('inner', []):
                        _resolve_tokens(c, node)
            else:
                # Stmt-named wrapper (e.g. ActionStmt, ImplicitPartStmt)
                # that has no direct source keyword — treat as structural
                # so the real child Stmt gets resolved.
                for c in node.get('inner', []):
                    _resolve(c)
                _propagate(node)
        else:
            for c in node.get('inner', []):
                _resolve(c)
            _propagate(node)

    def _resolve_tokens(node: Dict[str, Any], parent_stmt: Dict[str, Any]) -> None:
        """Try to locate leaf tokens within a statement's source range."""
        if 'range' not in parent_stmt:
            return
        kind = node.get('kind', '')
        val = node.get('value')
        if val and kind in ('Name', 'IntLiteralConstant', 'RealLiteralConstant',
                            'CharLiteralConstant', 'BOZLiteralConstant',
                            'LogicalLiteralConstant', 'ComplexLiteralConstant',
                            'Real'):
            pr = parent_stmt['range']
            bl, bc = pr['begin']['line'], pr['begin']['col']
            el, ec = pr['end']['line'], pr['end']['col']
            # try to find val in source range
            pat = re.compile(re.escape(val), re.IGNORECASE)
            for li in range(bl - 1, el):
                raw = source_lines[li].rstrip('\n\r')
                for m in pat.finditer(raw):
                    ms, me = m.start(), m.end()
                    if li == bl - 1 and ms < bc - 1:
                        continue
                    if li == el - 1 and me > ec:
                        continue
                    node['range'] = {
                        'begin': {'line': li + 1, 'col': ms + 1},
                        'end':   {'line': li + 1, 'col': me},
                    }
                    # Accept the first match within range
                    break
                if 'range' in node:
                    break
        for c in node.get('inner', []):
            _resolve_tokens(c, parent_stmt)

    _resolve(tree)

    # --- LabelDoStmt fixup: extend range to the labeled CONTINUE ---
    _fixup_labeled_do(tree, source_lines, code_info, is_fixed)


def _fixup_labeled_do(
    tree: Dict[str, Any],
    source_lines: List[str],
    code_info: List[Dict[str, Any]],
    is_fixed: bool,
) -> None:
    """For each LabelDoStmt, find the matching labeled CONTINUE / statement
    and extend range.end to cover it."""

    def _collect_labeled_do(node: Dict[str, Any],
                            out: List[Tuple[Dict[str, Any], str]]) -> None:
        if node.get('kind') == 'LabelDoStmt' and 'range' in node:
            # label stored in uint64_t child
            for c in node.get('inner', []):
                if c.get('kind') == 'uint64_t' and 'value' in c:
                    out.append((node, c['value']))
                    break
        for c in node.get('inner', []):
            _collect_labeled_do(c, out)

    labeled: List[Tuple[Dict[str, Any], str]] = []
    _collect_labeled_do(tree, labeled)
    if not labeled:
        return

    # Build list of (0-based line_idx, label_str) for every labeled source line.
    # A label can appear on many lines (different functions reuse labels).
    # We need to find the CLOSEST match AFTER each LabelDoStmt.
    labeled_source: List[Tuple[int, str]] = []
    for li, raw in enumerate(source_lines):
        stripped = raw.lstrip()
        m = re.match(r'^(\d+)\s', stripped)
        if m:
            lbl = m.group(1).lstrip('0') or '0'
            labeled_source.append((li, lbl))

    for node, lbl in labeled:
        lbl_norm = lbl.lstrip('0') or '0'
        do_line = node['range']['begin']['line']  # 1-based
        # Find the first labeled source line AFTER do_line with matching label
        for li, src_lbl in labeled_source:
            if li + 1 > do_line and src_lbl == lbl_norm:
                ec = len(source_lines[li].rstrip('\n\r'))
                node['range']['end'] = {'line': li + 1, 'col': max(ec, 1)}
                break


def _propagate(node: Dict[str, Any]) -> None:
    """Set *node* ``range`` from first/last child with a range."""
    children = node.get('inner', [])
    begin = end = None
    for c in children:
        if 'range' in c:
            begin = c['range']['begin']
            break
    for c in reversed(children):
        if 'range' in c:
            end = c['range']['end']
            break
    if begin and end:
        node['range'] = {'begin': dict(begin), 'end': dict(end)}


def _preprocess_source(
    source_lines: List[str], is_fixed: bool,
) -> List[Dict[str, Any]]:
    """Classify source lines as code or comment.

    Returns list (one per line) of ``{'is_code': bool, 'code': str}``.
    """
    result: List[Dict[str, Any]] = []
    for raw in source_lines:
        stripped = raw.strip()
        if not stripped:
            result.append({'is_code': False, 'code': ''})
            continue
        if is_fixed and len(raw) > 0 and raw[0] in 'Cc*!':
            result.append({'is_code': False, 'code': ''})
            continue
        if not is_fixed and stripped.startswith('!'):
            result.append({'is_code': False, 'code': ''})
            continue
        code = _strip_comment(raw.rstrip('\n\r'), is_fixed)
        result.append({
            'is_code': len(code.strip()) > 0,
            'code': code,
        })
    return result


def _strip_comment(line: str, is_fixed: bool) -> str:
    """Strip inline comment from a source line (respecting strings)."""
    in_str: Optional[str] = None
    for i, c in enumerate(line):
        if c in ("'", '"'):
            if in_str is None:
                in_str = c
            elif c == in_str:
                in_str = None
        elif c == '!' and in_str is None:
            return line[:i]
    return line


# ---------------------------------------------------------------------------
# Flag extraction
# ---------------------------------------------------------------------------

def extract_syntax_flags(flags: List[str]) -> List[str]:
    """Extract include / define / standard flags for syntax-only AST parsing.

    Keeps ``-I``, ``-D``, ``-U``, ``-std=``, ``-isystem`` etc. and drops
    everything else (optimisation, linking, warning flags ...).
    """
    out: List[str] = []
    skip_next = False
    KEEP_WITH_ARG = {'-I', '-isystem', '-iquote', '-isysroot', '-include',
                     '-idirafter', '-D', '-U'}
    KEEP_PREFIXES = ('-I', '-D', '-U', '-std=', '-isystem', '-iquote',
                     '-idirafter', '-include')
    for f in flags:
        if skip_next:
            skip_next = False
            out.append(f)
            continue
        if f in KEEP_WITH_ARG:
            out.append(f)
            skip_next = True
            continue
        if any(f.startswith(p) and len(f) > len(p) for p in KEEP_PREFIXES):
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Regex-based DO / END DO fallback
# ---------------------------------------------------------------------------

def parse_fortran_do_loops(source_file: str) -> Optional[List[Tuple[int, int, int, int]]]:
    """Extract DO / END DO loop ranges from Fortran source text.

    This is a lightweight regex-based fallback for when the flang AST
    parser is unavailable or fails.

    Returns list of (begin_line, begin_col, end_line, end_col) or *None*.
    """
    try:
        with open(source_file, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return None

    is_fixed = any(source_file.lower().endswith(ext)
                   for ext in ('.f', '.f77', '.fpp', '.for'))

    do_re    = re.compile(r'^\s*(?:\d+\s+)?\bDO\b', re.IGNORECASE)
    enddo_re = re.compile(r'^\s*END\s*DO\b', re.IGNORECASE)

    loops: List[Tuple[int, int, int, int]] = []
    do_stack: List[Tuple[int, int]] = []

    for i, line in enumerate(lines, 1):
        # Skip comment lines
        if is_fixed and len(line) > 0 and line[0] in 'Cc*!':
            continue
        stripped = line.lstrip()
        if stripped.startswith('!'):
            continue

        if enddo_re.match(stripped):
            if do_stack:
                bline, bcol = do_stack.pop()
                loops.append((bline, bcol, i, len(line.rstrip())))
            continue

        if do_re.match(stripped):
            col = len(line) - len(line.lstrip()) + 1
            do_stack.append((i, col))

    return loops if loops else None


# ---------------------------------------------------------------------------
# High-level convenience: AST with regex fallback
# ---------------------------------------------------------------------------

def get_loop_regions(
    source_file: str,
    flags: Optional[List[str]] = None,
    comp_dir: Optional[str] = None,
) -> Optional[List[Tuple[int, int, int, int]]]:
    """Get Fortran loop regions, trying the flang AST parser first.

    Falls back to :func:`parse_fortran_do_loops` (regex-based) when the
    AST parser is unavailable or produces no results.

    Parameters
    ----------
    source_file : str
        Path to the Fortran source file.
    flags : list[str] | None
        Raw compile flags (will be filtered to syntax-only flags).
    comp_dir : str | None
        Working directory for the flang invocation.

    Returns
    -------
    list[tuple] | None
        List of ``(begin_line, begin_col, end_line, end_col)``, or *None*.
    """
    try:
        syntax_flags = extract_syntax_flags(flags) if flags else []
        ast = parse_fortran_ast(source_file, flags=syntax_flags,
                                comp_dir=comp_dir)
        if ast is not None:
            loops = extract_loop_regions(ast)
            if loops:
                return loops
    except Exception:
        pass
    # Fallback: regex-based DO / END DO parsing
    return parse_fortran_do_loops(source_file)


# ---------------------------------------------------------------------------
# CLI helper for quick testing
# ---------------------------------------------------------------------------

def _dump_tree(node: Dict[str, Any], indent: int = 0) -> None:
    """Pretty-print a parsed tree to stdout."""
    prefix = '  ' * indent
    kind = node.get('kind', '?')
    parts = [f'{prefix}{kind}']
    if 'value' in node:
        parts.append(f" = '{node['value']}'")
    if 'range' in node:
        r = node['range']
        parts.append(f"  <{r['begin']['line']}:{r['begin']['col']}"
                     f"-{r['end']['line']}:{r['end']['col']}>")
    print(''.join(parts))
    for c in node.get('inner', []):
        _dump_tree(c, indent + 1)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <fortran-file> [flags...]')
        sys.exit(1)
    src = sys.argv[1]
    extra = sys.argv[2:] if len(sys.argv) > 2 else None
    ast = parse_fortran_ast(src, flags=extra)
    if ast is None:
        print('Failed to parse', file=sys.stderr)
        sys.exit(1)
    _dump_tree(ast)
    print()
    loops = extract_loop_regions(ast)
    print(f'Loops ({len(loops)}):')
    for l in loops:
        print(f'  L{l[0]}:{l[1]} – L{l[2]}:{l[3]}')
