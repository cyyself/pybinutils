#!/usr/bin/env python3
"""Parse C/C++ source via clang JSON AST dump into a structured Python dict.

Wraps ``clang -Xclang -ast-dump=json -fsyntax-only`` to produce a full
AST dict (the raw JSON) and provides helpers to extract source regions
for loops and other constructs.

Written by Claude Opus 4.6.

Public API
----------
parse_clang_ast(source_file, language=None, flags=None, comp_dir=None,
                clang='clang')
    → dict  (the raw clang JSON AST), or *None* on failure.

extract_loop_regions(ast_dict, source_file=None)
    → list of (begin_line, begin_col, end_line, end_col).

extract_syntax_flags(flags)
    → list of flags suitable for syntax-only AST parsing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Flag extraction
# ---------------------------------------------------------------------------

def extract_syntax_flags(flags: List[str]) -> List[str]:
    """Extract include / define / standard flags for syntax-only AST parsing.

    Keeps ``-I``, ``-D``, ``-U``, ``-std=``, ``-isystem`` etc. and drops
    everything else (optimisation, linking, warning flags …).
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
# Public API
# ---------------------------------------------------------------------------

def parse_clang_ast(
    source_file: str,
    language: Optional[str] = None,
    flags: Optional[List[str]] = None,
    comp_dir: Optional[str] = None,
    clang: str = 'clang',
) -> Optional[Dict[str, Any]]:
    """Run clang JSON AST dump and return the parsed dict.

    Parameters
    ----------
    source_file : str
        Path to the C or C++ source file.
    language : str | None
        ``'C'``, ``'C++'``, or *None* (auto-detect from extension).
    flags : list[str] | None
        Extra compile flags; only syntax-relevant flags are kept.
    comp_dir : str | None
        Working directory for the clang invocation.
    clang : str
        Path to the clang binary.  For C++ files the ``++`` suffix is
        added automatically when *language* starts with ``'C++'``.

    Returns
    -------
    dict | None
        The full clang JSON AST, or *None* on failure.
    """
    if language is None:
        language = _detect_language(source_file)

    compiler = clang
    if language and language.startswith('C++'):
        # Ensure we use clang++
        if not compiler.endswith('++'):
            compiler = compiler + '++'

    cmd: List[str] = [compiler, '-Xclang', '-ast-dump=json', '-fsyntax-only']
    if flags:
        cmd.extend(extract_syntax_flags(flags))
    cmd.append(source_file)

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, cwd=comp_dir,
        )
        if r.returncode != 0:
            msg = r.stderr.splitlines()[0] if r.stderr else '(unknown error)'
            print(f"clang AST failed for {source_file}: {msg}",
                  file=sys.stderr)
            return None
    except Exception as e:
        print(f"clang AST error for {source_file}: {e}", file=sys.stderr)
        return None

    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as e:
        print(f"clang AST JSON decode error: {e}", file=sys.stderr)
        return None


def extract_loop_regions(
    ast: Dict[str, Any],
    source_file: Optional[str] = None,
) -> List[Tuple[int, int, int, int]]:
    """Walk a clang JSON AST and return loop regions.

    Parameters
    ----------
    ast : dict
        The clang JSON AST (as returned by :func:`parse_clang_ast`).
    source_file : str | None
        If given, only loops whose locations resolve to this file are
        returned.  Useful when a translation unit includes headers.

    Returns
    -------
    list of (begin_line, begin_col, end_line, end_col)
    """
    LOOP_KINDS = {'ForStmt', 'WhileStmt', 'DoStmt', 'CXXForRangeStmt'}
    loops: List[Tuple[int, int, int, int]] = []
    source_base = os.path.basename(source_file) if source_file else None

    def _get_loc(
        loc_dict: Optional[Dict[str, Any]],
        last_line: int = 0,
        last_col: int = 0,
        last_file: Optional[str] = None,
    ) -> Tuple[int, int, Optional[str]]:
        """Extract (line, col, file) from a clang source location dict."""
        if not loc_dict:
            return last_line, last_col, last_file
        if 'expansionLoc' in loc_dict:
            loc_dict = loc_dict['expansionLoc']
        line = loc_dict.get('line', last_line)
        col = loc_dict.get('col', last_col)
        file = loc_dict.get('file', last_file)
        return line, col, file

    def _walk(
        node: Dict[str, Any],
        last_line: int = 0,
        last_col: int = 0,
        last_file: Optional[str] = None,
    ) -> None:
        if not isinstance(node, dict):
            return
        loc = node.get('loc', {})
        nl, nc, nf = _get_loc(loc, last_line, last_col, last_file)

        if node.get('kind', '') in LOOP_KINDS:
            rng = node.get('range', {})
            bl, bc, bf = _get_loc(rng.get('begin', {}), nl, nc, nf)
            el, ec, ef = _get_loc(rng.get('end', {}), nl, nc, nf)
            if bl > 0 and el > 0:
                # Filter by source file if requested
                if source_base is None or _file_matches(bf, source_base):
                    loops.append((bl, bc, el, ec))

        for child in node.get('inner', []):
            _walk(child, nl, nc, nf)

    _walk(ast)
    return loops


def extract_loop_regions_by_file(
    ast: Dict[str, Any],
    source_file: Optional[str] = None,
) -> Dict[str, List[Tuple[int, int, int, int]]]:
    """Walk a clang JSON AST and return loop regions grouped by source file.

    Unlike :func:`extract_loop_regions`, this returns loops from *all* files
    in the translation unit (including ``#include``d headers), grouped by
    their source file path.

    Parameters
    ----------
    ast : dict
        The clang JSON AST (as returned by :func:`parse_clang_ast`).
    source_file : str | None
        Default file path to assign when the AST does not carry explicit
        file info for a node (typically the main translation-unit file).

    Returns
    -------
    dict mapping file path → list of (begin_line, begin_col, end_line, end_col)
    """
    from collections import defaultdict

    LOOP_KINDS = {'ForStmt', 'WhileStmt', 'DoStmt', 'CXXForRangeStmt'}
    loops_by_file: Dict[str, List[Tuple[int, int, int, int]]] = defaultdict(list)

    def _get_loc(
        loc_dict: Optional[Dict[str, Any]],
        last_line: int = 0,
        last_col: int = 0,
        last_file: Optional[str] = None,
    ) -> Tuple[int, int, Optional[str]]:
        if not loc_dict:
            return last_line, last_col, last_file
        if 'expansionLoc' in loc_dict:
            loc_dict = loc_dict['expansionLoc']
        line = loc_dict.get('line', last_line)
        col = loc_dict.get('col', last_col)
        file = loc_dict.get('file', last_file)
        return line, col, file

    def _walk(
        node: Dict[str, Any],
        last_line: int = 0,
        last_col: int = 0,
        last_file: Optional[str] = None,
    ) -> None:
        if not isinstance(node, dict):
            return
        loc = node.get('loc', {})
        nl, nc, nf = _get_loc(loc, last_line, last_col, last_file)

        if node.get('kind', '') in LOOP_KINDS:
            rng = node.get('range', {})
            bl, bc, bf = _get_loc(rng.get('begin', {}), nl, nc, nf)
            el, ec, ef = _get_loc(rng.get('end', {}), nl, nc, nf)
            if bl > 0 and el > 0:
                key = bf if bf else (source_file or '')
                if key:
                    loops_by_file[key].append((bl, bc, el, ec))

        for child in node.get('inner', []):
            _walk(child, nl, nc, nf)

    _walk(ast)
    return dict(loops_by_file)


def extract_regions(
    ast: Dict[str, Any],
    kinds: set,
    source_file: Optional[str] = None,
) -> List[Tuple[str, int, int, int, int]]:
    """Walk a clang JSON AST and return regions of given AST node kinds.

    Returns list of (kind, begin_line, begin_col, end_line, end_col).
    """
    regions: List[Tuple[str, int, int, int, int]] = []
    source_base = os.path.basename(source_file) if source_file else None

    def _get_loc(loc_dict, last_line=0, last_col=0, last_file=None):
        if not loc_dict:
            return last_line, last_col, last_file
        if 'expansionLoc' in loc_dict:
            loc_dict = loc_dict['expansionLoc']
        return (loc_dict.get('line', last_line),
                loc_dict.get('col', last_col),
                loc_dict.get('file', last_file))

    def _walk(node, last_line=0, last_col=0, last_file=None):
        if not isinstance(node, dict):
            return
        loc = node.get('loc', {})
        nl, nc, nf = _get_loc(loc, last_line, last_col, last_file)
        kind = node.get('kind', '')
        if kind in kinds:
            rng = node.get('range', {})
            bl, bc, bf = _get_loc(rng.get('begin', {}), nl, nc, nf)
            el, ec, ef = _get_loc(rng.get('end', {}), nl, nc, nf)
            if bl > 0 and el > 0:
                if source_base is None or _file_matches(bf, source_base):
                    regions.append((kind, bl, bc, el, ec))
        for child in node.get('inner', []):
            _walk(child, nl, nc, nf)

    _walk(ast)
    return regions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_language(source_file: str) -> str:
    """Guess language from file extension."""
    ext = os.path.splitext(source_file)[1].lower()
    if ext in ('.cpp', '.cxx', '.cc', '.C', '.hpp', '.hxx'):
        return 'C++'
    return 'C'


def _file_matches(
    file_path: Optional[str], base_name: str,
) -> bool:
    """Check if *file_path* ends with *base_name*."""
    if file_path is None:
        return True  # no file info → assume same TU
    return os.path.basename(file_path) == base_name


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------

def _dump_loops(ast: Dict[str, Any], source_file: Optional[str] = None) -> None:
    """Pretty-print loop regions to stdout."""
    loops = extract_loop_regions(ast, source_file)
    print(f'Loops ({len(loops)}):')
    for bl, bc, el, ec in loops:
        print(f'  L{bl}:{bc} – L{el}:{ec}')


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(
        description='Dump clang JSON AST loop regions',
        usage='%(prog)s [options] source [-- extra-flags...]',
    )
    p.add_argument('source', help='C/C++ source file')
    p.add_argument('--language', '-l', default=None,
                   help='Language (C, C++); auto-detected if omitted')
    p.add_argument('--clang', default='clang', help='Path to clang binary')
    args, extra = p.parse_known_args()
    # Strip leading '--' separator if present
    if extra and extra[0] == '--':
        extra = extra[1:]

    ast = parse_clang_ast(args.source, language=args.language,
                          flags=extra if extra else None, clang=args.clang)
    if ast is None:
        print('Failed to parse', file=sys.stderr)
        sys.exit(1)

    # Print summary
    print(f"AST root kind: {ast.get('kind', '?')}")
    inner = ast.get('inner', [])
    print(f"Top-level declarations: {len(inner)}")
    _dump_loops(ast, args.source)
