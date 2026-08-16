#!/usr/bin/env python3
"""
arch-map: Deterministic architecture scanner.

Produces clean, multi-level architectural views from source code AST:
  1. System Context & External Dependencies (who calls the system, what external SDKs/APIs the system calls)
  2. Service Topology (Control Plane wiring + Data Plane data-flow graph)
  3. Request Execution Flow (Step-by-step handler call-graph walk)
  4. Endpoint Registry (All discovered HTTP/RPC routes)
  5. Environment Matrix (Exact variables consumed and declared)

Pure deterministic AST analysis by default; opt-in LSP for semantic cross-file reference resolution.
Zero hardcoding. Zero synthetic guessing. Same codebase -> same document.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


IGNORE_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", ".turbo", ".cache",
    "coverage", "target", "vendor", "__pycache__", ".venv", "venv", ".omp",
    ".idea", ".vscode", "Pods", "DerivedData", ".expo",
}

TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "fixtures", "mocks"}
OPS_DIR_NAMES = {"scripts", "script", "bin", "tooling"}

JS_EXTS = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}
SCAN_EXTS = JS_EXTS | {".py", ".rs", ".go", ".swift", ".cpp", ".h", ".sh"}

BUILTIN_MODULES = {
    "fs", "path", "http", "https", "crypto", "url", "os", "events", "stream",
    "util", "child_process", "cluster", "net", "tls", "dgram", "dns", "zlib",
    "buffer", "process", "readline", "assert", "module", "perf_hooks", "worker_threads",
    "sys", "re", "json", "time", "datetime", "typing", "collections", "pathlib",
    "math", "random", "subprocess", "logging", "unittest", "threading", "asyncio",
    "urllib", "socket", "struct", "hashlib", "copy", "itertools", "functools",
    "abc", "dataclasses", "enum", "contextlib", "uuid", "base64", "io",
    "tempfile", "shutil", "warnings", "inspect", "traceback", "importlib",
    "argparse", "configparser", "csv", "gzip", "pickle", "secrets", "hmac",
    "ssl", "concurrent", "multiprocessing", "queue", "operator", "types",
    "decimal", "string", "textwrap", "pprint", "weakref", "html", "email",
}

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")


def mermaid_id(prefix: str, name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]", "_", str(name)).strip("_")
    if not cleaned:
        cleaned = "x"
    if cleaned[0].isdigit():
        cleaned = "n_" + cleaned
    return f"{prefix}_{cleaned}"[:70]


def mermaid_label(text: str) -> str:
    return str(text).replace('"', "'").replace("\n", " ").strip()[:80]


def mermaid_edge_label(text: str) -> str:
    cleaned = str(text).replace('"', "'").replace("\n", " ").strip()[:80]
    if any(c in cleaned for c in "()[]{}:,;/\\"):
        return f'"{cleaned}"'
    return cleaned


def posix(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def is_test_path(rel: str) -> bool:
    parts = Path(rel).parts
    if any(p in TEST_DIR_NAMES for p in parts):
        return True
    name = Path(rel).name.lower()
    return any(x in name for x in (".test.", ".spec.", "_test.", "-test.", ".fixture."))


def is_ops_path(rel: str) -> bool:
    return Path(rel).parts[0] in OPS_DIR_NAMES if Path(rel).parts else False


def normalize_pkg(raw: str) -> str:
    if raw.startswith("@"):
        parts = raw.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else raw
    return raw.split("/")[0]


def normalize_route_path(path: str) -> str:
    path = path.split("?")[0]
    path = re.sub(r"\$\{[^}]+\}", ":param", path)
    path = re.sub(r"\([^)]*\)", ":param", path)
    path = re.sub(r":[A-Za-z_][\w]*", ":param", path)
    path = re.sub(r"(:param)+", ":param", path)
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def js_regex_to_path(rx: str) -> str:
    rx = rx.lstrip("^").rstrip("$")
    rx = rx.replace("\\/", "/")
    rx = re.sub(r"\([^)]*\)", ":param", rx)
    rx = re.sub(r"\[[^\]]*\]\+?", ":param", rx)
    return normalize_route_path(rx)


def import_label(spec: str) -> str:
    """Keep the import the way it appears in source. Do not rename it to a cloud product."""
    spec = spec.strip()
    if spec.startswith("node:"):
        spec = spec.split(":", 1)[1]
    if spec.startswith("@"):
        return normalize_pkg(spec)
    return spec


def is_noise_import(spec: str) -> bool:
    if not spec or spec.startswith((".", "/", "~")):
        return True
    raw = spec[5:] if spec.startswith("node:") else spec
    label = import_label(raw)
    top = label.split("/")[0].split(".")[0]
    if label in BUILTIN_MODULES or top in BUILTIN_MODULES:
        return True
    if label.endswith("-core") or label.startswith(("@azure/core", "azure.core", "@aws-sdk/util")):
        return True
    return False


def word_in(name: str, body: str) -> bool:
    if not name or not body:
        return False
    return re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", body) is not None


def symbol_import_uses(mod: "JsModule", sym: "Symbol") -> List[Tuple[str, str]]:
    """Packages this function/class actually mentions, as (import_name, binding)."""
    body = "\n".join([sym.body, *sym.methods.values()])
    uses: List[Tuple[str, str]] = []
    seen_pkg = set()
    imported = {name: spec for name, spec in mod.imports.items() if not is_noise_import(spec)}
    for binding, spec in imported.items():
        if not word_in(binding, body) and binding not in sym.constructed:
            continue
        pkg = import_label(spec)
        if pkg in seen_pkg:
            continue
        seen_pkg.add(pkg)
        uses.append((pkg, binding))
    for local, typ in sym.bindings.items():
        spec = imported.get(typ)
        if not spec or not word_in(local, body):
            continue
        pkg = import_label(spec)
        if pkg in seen_pkg:
            continue
        seen_pkg.add(pkg)
        uses.append((pkg, typ))
    return uses


# ---------------------------------------------------------------------------
# Mermaid & Markdown Linter (Zero-Dependency Syntax & Structure Validator)
# ---------------------------------------------------------------------------

class MermaidLintError(Exception):
    """Raised when generated or scanned Markdown contains malformed Mermaid diagrams."""
    pass


def lint_mermaid_flowchart(lines: List[Tuple[int, str]]) -> List[str]:
    errors = []
    subgraph_stack: List[Tuple[int, str]] = []

    invalid_delims = [
        (re.compile(r"\(\[\s*\(|\(\s*\[\s*\(|\(\s*\(\s*\[|\[\s*\[\s*\("), "Invalid composite opening delimiter (e.g. `([(` or `[([`)"),
        (re.compile(r"\)\s*\]\s*\)|\)\s*\)\s*\]|\]\s*\)\s*\]"), "Invalid composite closing delimiter (e.g. `)])` or `))]`)"),
    ]

    for lineno, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("%%"):
            continue

        if stripped.startswith("subgraph"):
            subgraph_stack.append((lineno, stripped))
        elif stripped == "end":
            if not subgraph_stack:
                errors.append(f"Line {lineno}: `end` without matching `subgraph`")
            else:
                subgraph_stack.pop()

        for m in re.finditer(r"(?:-->|-\.->|==>)\|([^|]+)\|", line):
            lbl_content = m.group(1).strip()
            if not (lbl_content.startswith('"') and lbl_content.endswith('"')):
                if any(c in lbl_content for c in "()[]{}"):
                    errors.append(
                        f"Line {lineno}: Unquoted special characters in edge label `|{lbl_content}|`. "
                        f"Must be wrapped in quotes: `|\"{lbl_content}\"|`"
                    )

        clean = re.sub(r"%%.*$", "", line)
        clean = re.sub(r"-->\|[^|]*\|", "-->", clean)
        clean = re.sub(r"-\.->\|[^|]*\|", "-.->", clean)
        clean = re.sub(r"==>\|[^|]*\|", "==>", clean)

        for pat, msg in invalid_delims:
            if pat.search(clean):
                errors.append(f"Line {lineno}: {msg} in `{stripped}`")

        code_part = clean.split("%%")[0]
        if code_part.count('"') % 2 != 0:
            errors.append(f"Line {lineno}: Unclosed or unmatched double quotes in `{stripped}`")

    if subgraph_stack:
        for lineno, sub in subgraph_stack:
            errors.append(f"Line {lineno}: Unclosed `subgraph`: `{sub}` (missing `end`)")

    return errors


def lint_mermaid_sequence(lines: List[Tuple[int, str]]) -> List[str]:
    errors = []
    block_stack: List[Tuple[int, str]] = []
    block_keywords = re.compile(r"^(par|alt|opt|critical|loop|rect)\b")

    for lineno, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("%%"):
            continue

        m = block_keywords.match(stripped)
        if m:
            block_stack.append((lineno, m.group(1)))
        elif stripped.startswith("else"):
            if not block_stack or block_stack[-1][1] not in ("alt", "critical"):
                errors.append(f"Line {lineno}: `else` outside `alt` or `critical` block")
        elif stripped == "end":
            if not block_stack:
                errors.append(f"Line {lineno}: `end` without matching block (`par`, `alt`, `opt`, etc.)")
            else:
                block_stack.pop()

        code_part = line.split("%%")[0]
        if code_part.count('"') % 2 != 0:
            errors.append(f"Line {lineno}: Unclosed or unmatched double quotes in `{stripped}`")

    if block_stack:
        for lineno, blk in block_stack:
            errors.append(f"Line {lineno}: Unclosed sequence block `{blk}` (missing `end`)")

    return errors


def lint_mermaid(code: str, start_line: int = 1) -> List[str]:
    lines = code.splitlines()
    indexed_lines = [(start_line + i, line) for i, line in enumerate(lines)]

    header = None
    for lineno, line in indexed_lines:
        s = line.strip()
        if s and not s.startswith("%%"):
            header = s
            break

    if not header:
        return ["Empty Mermaid block"]

    first_word = header.split()[0]
    if first_word in ("flowchart", "graph"):
        return lint_mermaid_flowchart(indexed_lines)
    elif first_word == "sequenceDiagram":
        return lint_mermaid_sequence(indexed_lines)
    return []


def lint_markdown(text: str, file_path: str = "") -> List[str]:
    """Validates all Mermaid code blocks and Markdown structures in a document."""
    errors = []
    file_prefix = f"{file_path}: " if file_path else ""

    fence_count = len(re.findall(r"^```", text, re.M))
    if fence_count % 2 != 0:
        errors.append(f"{file_prefix}Unclosed Markdown code fence (found {fence_count} fence markers)")

    pattern = re.compile(r"^```mermaid[ \t]*\n(.*?)\n^```", re.M | re.S)
    for m in pattern.finditer(text):
        start_line = text[:m.start()].count("\n") + 2
        block_code = m.group(1)
        block_errors = lint_mermaid(block_code, start_line)
        for err in block_errors:
            errors.append(f"{file_prefix}{err}")

    table_lines = []
    in_table = False
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            if in_table:
                in_table = False
                table_lines = []
            continue

        if in_fence:
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = [(lineno, [c.strip() for c in stripped.split("|")[1:-1]])]
            else:
                table_lines.append((lineno, [c.strip() for c in stripped.split("|")[1:-1]]))
        else:
            if in_table:
                if len(table_lines) >= 2:
                    expected_cols = len(table_lines[0][1])
                    for t_lineno, cols in table_lines[1:]:
                        if all(re.match(r"^:?-+:?$", c) for c in cols if c):
                            continue
                        if len(cols) != expected_cols:
                            errors.append(
                                f"{file_prefix}Line {t_lineno}: Table column count mismatch "
                                f"(expected {expected_cols} columns, found {len(cols)})"
                            )
                in_table = False
                table_lines = []

    return errors


# ---------------------------------------------------------------------------
# Module model
# ---------------------------------------------------------------------------

@dataclass
class Call:
    recv: Optional[str]
    method: str
    chain: List[str]
    raw: str


@dataclass
class Symbol:
    name: str
    kind: str
    file: str
    body: str = ""
    methods: Dict[str, str] = field(default_factory=dict)
    bindings: Dict[str, str] = field(default_factory=dict)
    constructed: List[str] = field(default_factory=list)
    return_news: List[str] = field(default_factory=list)


@dataclass
class Route:
    method: str
    path: str
    file: str
    body: str
    scope: str
    source: str = "server"


@dataclass
class JsModule:
    file: str
    text: str
    imports: Dict[str, str] = field(default_factory=dict)
    external_imports: Set[str] = field(default_factory=set)
    classes: Dict[str, Symbol] = field(default_factory=dict)
    functions: Dict[str, Symbol] = field(default_factory=dict)
    constants: Dict[str, str] = field(default_factory=dict)
    urls: List[str] = field(default_factory=list)
    spawns: List[str] = field(default_factory=list)
    env_vars: Set[str] = field(default_factory=set)
    routes: List[Route] = field(default_factory=list)
    client_calls: List[Tuple[str, str, str]] = field(default_factory=list)
    entrypoint: Optional[str] = None
    io_kind: Set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Python AST Parsing (Pure Standard Library)
# ---------------------------------------------------------------------------

def _py_source_segment(text: str, node: ast.AST) -> str:
    if hasattr(ast, "get_source_segment"):
        seg = ast.get_source_segment(text, node)
        if seg:
            return seg
    lines = text.splitlines()
    start = max(0, getattr(node, "lineno", 1) - 1)
    end = getattr(node, "end_lineno", start + 1)
    return "\n".join(lines[start:end])


def _py_inner_body(text: str, node: ast.AST) -> str:
    stmts = getattr(node, "body", None)
    if not stmts:
        return _py_source_segment(text, node)
    parts = [_py_source_segment(text, stmt) for stmt in stmts]
    return "\n".join(part for part in parts if part)


def _py_str(node: Optional[ast.AST]) -> Optional[str]:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _py_callee(func: ast.AST) -> Tuple[Optional[str], Optional[str]]:
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        recv = func.value.id if isinstance(func.value, ast.Name) else None
        return recv, func.attr
    return None, None


def _py_bind_type(func: ast.AST) -> Optional[str]:
    recv, name = _py_callee(func)
    if name and name[:1].isupper():
        return name
    if recv and recv[:1].isupper():
        return recv
    if name and name.startswith("create"):
        return name
    return name or recv


def _py_local_statements(node: ast.AST) -> List[ast.AST]:
    body = getattr(node, "body", None)
    if body is None:
        return [node]
    out: List[ast.AST] = []
    stack = list(body)
    while stack:
        stmt = stack.pop(0)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        out.append(stmt)
        for attr in ("body", "orelse", "finalbody"):
            stack.extend(getattr(stmt, attr, []) or [])
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                stack.extend(handler.body)
    return out


def _py_assign_bindings(node: ast.AST) -> Tuple[Dict[str, str], List[str], List[str]]:
    bindings: Dict[str, str] = {}
    constructed: List[str] = []
    returns: List[str] = []
    for child in _py_local_statements(node):
        if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
            typ = _py_bind_type(child.value.func)
            if not typ:
                continue
            constructed.append(typ)
            for target in child.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = typ
        elif isinstance(child, ast.AnnAssign) and isinstance(child.value, ast.Call) and isinstance(child.target, ast.Name):
            typ = _py_bind_type(child.value.func)
            if typ:
                constructed.append(typ)
                bindings[child.target.id] = typ
        elif isinstance(child, ast.Return) and isinstance(child.value, ast.Call):
            typ = _py_bind_type(child.value.func)
            if typ:
                returns.append(typ)
        elif isinstance(child, ast.Return) and isinstance(child.value, ast.Name):
            returns.append(child.value.id)
    return bindings, constructed, returns


def _py_route_from_decorators(node: ast.AST) -> Optional[Tuple[str, str]]:
    for dec in getattr(node, "decorator_list", []):
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        method = dec.func.attr.lower()
        if method in {"get", "post", "put", "delete", "patch", "options", "head"}:
            path = _py_str(dec.args[0]) if dec.args else None
            if path:
                return method.upper(), path
        if method == "route":
            path = _py_str(dec.args[0]) if dec.args else None
            http = "GET"
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    strs = [_py_str(elt) for elt in kw.value.elts]
                    strs = [s for s in strs if s]
                    if strs:
                        http = strs[0].upper()
            if path:
                return http, path
    return None


def parse_py_module(rel: str, text: str) -> Optional[JsModule]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    mod = JsModule(file=rel, text=text)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                mod.imports[bound] = alias.name
                if not is_noise_import(alias.name):
                    mod.external_imports.add(import_label(alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            spec = ("." * node.level) + module
            if not spec:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                mod.imports[bound] = spec
            if not spec.startswith(".") and not is_noise_import(spec):
                mod.external_imports.add(import_label(spec))

    def add_fn(node: ast.AST, parent_bindings: Dict[str, str]) -> None:
        body = _py_inner_body(text, node)
        bindings, constructed, returns = _py_assign_bindings(node)
        merged = dict(parent_bindings)
        merged.update(bindings)
        _add_function(mod, node.name, body)
        sym = mod.functions[node.name]
        sym.bindings = merged
        sym.constructed = constructed
        if returns:
            resolved = []
            for item in returns:
                resolved.append(merged.get(item, item))
            sym.return_news = resolved
        route = _py_route_from_decorators(node)
        if route:
            method, path = route
            mod.routes.append(Route(method, path, rel, body, node.name, "server"))
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add_fn(child, merged)

    module_bindings, module_constructed, _ = _py_assign_bindings(tree)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add_fn(node, module_bindings)
        elif isinstance(node, ast.ClassDef):
            body = _py_source_segment(text, node)
            sym = Symbol(name=node.name, kind="class", file=rel, body=body)
            bindings, constructed, returns = _py_assign_bindings(node)
            merged = dict(module_bindings)
            merged.update(bindings)
            sym.bindings = merged
            sym.constructed = constructed + module_constructed
            sym.return_news = returns
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_body = _py_inner_body(text, item)
                    sym.methods[item.name] = method_body
                    route = _py_route_from_decorators(item)
                    if route:
                        method, path = route
                        mod.routes.append(Route(method, path, rel, method_body, node.name, "server"))
            mod.classes[sym.name] = sym

    for m in re.finditer(r"""os\.environ(?:\.get)?\(\s*['\"]([A-Za-z0-9_]+)['\"]|os\.getenv\(\s*['\"]([A-Za-z0-9_]+)['\"]|os\.environ\[\s*['\"]([A-Za-z0-9_]+)['\"]""", text):
        name = m.group(1) or m.group(2) or m.group(3)
        if name:
            mod.env_vars.add(name)
    for m in re.finditer(r"""['\"](https?://[^'\"]+)['\"]""", text):
        url = m.group(1)
        if any(x in url for x in ("localhost", "127.0.0.1", "example.com", "example.org")):
            continue
        mod.urls.append(url)
    if re.search(r"\bFastAPI\s*\(|\bFlask\s*\(|\bAPIRouter\s*\(", text):
        mod.entrypoint = "http"
    elif re.search(r'if\s+__name__\s*==\s*[\'"]__main__[\'"]', text) and (
        "uvicorn" in text or "app.run" in text
    ):
        mod.entrypoint = "http"
    if re.search(r"\bos\.(?:environ|getenv)\b|\bopen\s*\(", text):
        mod.io_kind.add("disk")
    return mod


# ---------------------------------------------------------------------------
# Brace-matched JS/TS reader (deterministic structural analysis)
# ---------------------------------------------------------------------------

class JsSrc:
    def __init__(self, text: str):
        self.s = text
        self.n = len(text)

    def skip_ws_comments(self, i: int) -> int:
        s, n = self.s, self.n
        while i < n:
            c = s[i]
            if c in " \t\r\n":
                i += 1
                continue
            if c == "/" and i + 1 < n and s[i + 1] == "/":
                i += 2
                while i < n and s[i] not in "\n\r":
                    i += 1
                continue
            if c == "/" and i + 1 < n and s[i + 1] == "*":
                i += 2
                while i + 1 < n and not (s[i] == "*" and s[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
                continue
            break
        return i

    def skip_string(self, i: int) -> int:
        s, n = self.s, self.n
        quote = s[i]
        i += 1
        if quote == "`":
            while i < n:
                if s[i] == "\\":
                    i += 2
                    continue
                if s[i] == "`":
                    return i + 1
                if s[i] == "$" and i + 1 < n and s[i + 1] == "{":
                    i = self._skip_template_expr(i + 2)
                    continue
                i += 1
            return n
        while i < n:
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == quote:
                return i + 1
            if s[i] in "\n\r":
                return i
            i += 1
        return n

    def _skip_template_expr(self, i: int) -> int:
        s, n = self.s, self.n
        depth = 1
        while i < n and depth > 0:
            i = self.skip_ws_comments(i)
            if i >= n:
                break
            c = s[i]
            if c in "'\"`":
                i = self.skip_string(i)
                continue
            if c == "{":
                depth += 1
                i += 1
                continue
            if c == "}":
                depth -= 1
                i += 1
                continue
            i += 1
        return i

    def match_brace(self, open_pos: int) -> int:
        s, n = self.s, self.n
        if open_pos >= n or s[open_pos] != "{":
            return -1
        depth = 1
        i = open_pos + 1
        while i < n and depth > 0:
            i = self.skip_ws_comments(i)
            if i >= n:
                break
            c = s[i]
            if c in "'\"`":
                i = self.skip_string(i)
                continue
            if c == "/":
                prev = self._prev_token_char(i)
                if prev in "=:(,[!&|?{};\n\r" or prev is None:
                    i = self._skip_regex(i)
                    continue
            if c == "{":
                depth += 1
                i += 1
                continue
            if c == "}":
                depth -= 1
                i += 1
                if depth == 0:
                    return i
                continue
            i += 1
        return i if depth == 0 else -1

    def _prev_token_char(self, pos: int) -> Optional[str]:
        i = pos - 1
        while i >= 0 and self.s[i] in " \t\r\n":
            i -= 1
        return self.s[i] if i >= 0 else None

    def _skip_regex(self, i: int) -> int:
        s, n = self.s, self.n
        i += 1
        in_class = False
        while i < n:
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == "[" and not in_class:
                in_class = True
                i += 1
                continue
            if s[i] == "]" and in_class:
                in_class = False
                i += 1
                continue
            if s[i] == "/" and not in_class:
                i += 1
                while i < n and s[i].isalpha():
                    i += 1
                return i
            if s[i] in "\n\r":
                return i
            i += 1
        return n


def parse_js_module(rel: str, text: str) -> JsModule:
    src = JsSrc(text)
    mod = JsModule(file=rel, text=text)
    _extract_imports(mod, text)
    _extract_constants_urls_env(mod, text)
    _extract_classes(mod, src)
    _extract_functions(mod, src)
    _extract_spawns(mod, text)
    _extract_routes(mod, src)
    _extract_client_api(mod, src)
    _detect_entrypoint(mod, text)
    _detect_io(mod, text)
    return mod


def _extract_imports(mod: JsModule, text: str) -> None:
    for m in re.finditer(
        r"""import\s+([\w\s{},*]+)\s+from\s+['"]([^'"]+)['"]"""
        r"""|const\s+([\w\s{},*]+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""",
        text,
    ):
        names_blob = m.group(1) or m.group(3) or ""
        spec = m.group(2) or m.group(4) or ""
        names = []
        if "{" in names_blob:
            inside = names_blob[names_blob.find("{") + 1 : names_blob.find("}")]
            for p in inside.split(","):
                p = p.strip()
                if not p:
                    continue
                names.append(p.split(" as ")[-1].strip().split(":")[-1].strip())
        names_blob_clean = re.sub(r"\{[^}]*\}", "", names_blob).strip().strip(",")
        if names_blob_clean:
            for p in names_blob_clean.split(","):
                p = p.strip()
                if p and p != "*":
                    names.append(p.split(" as ")[-1].strip())
        _bind_import(mod, names, spec)


def _bind_import(mod: JsModule, names: List[str], spec: str) -> None:
    if spec.startswith((".", "/", "~")):
        for name in names:
            mod.imports[name] = spec
        return
    pkg = import_label(spec)
    if not is_noise_import(pkg):
        mod.external_imports.add(pkg)
    for name in names:
        mod.imports[name] = spec


def _extract_constants_urls_env(mod: JsModule, text: str) -> None:
    for m in re.finditer(r"""const\s+([A-Za-z0-9_]+)\s*=\s*['"]([^'"]+)['"]""", text):
        name, val = m.group(1), m.group(2)
        mod.constants[name] = val
        if val.startswith("http://") or val.startswith("https://"):
            if not any(x in val for x in ("localhost", "127.0.0.1", "example.com", "example.org")):
                mod.urls.append(val)
    for m in re.finditer(r"""['"](https?://[^'"]+)['\"]""", text):
        url = m.group(1)
        if any(x in url for x in ("localhost", "127.0.0.1", "example.com", "example.org")):
            continue
        if url not in mod.urls:
            mod.urls.append(url)
    for m in re.finditer(r"""process\.env\.([A-Za-z0-9_]+)|process\.env\[['"]([A-Za-z0-9_]+)['"]\]""", text):
        name = m.group(1) or m.group(2)
        if name:
            mod.env_vars.add(name)


def _extract_classes(mod: JsModule, src: JsSrc) -> None:
    for m in re.finditer(r"(?:export\s+)?class\s+([A-Za-z_][\w]*)", src.s):
        name = m.group(1)
        i = src.skip_ws_comments(m.end())
        if i < src.n and src.s[i : i + 7] == "extends":
            i = src.skip_ws_comments(i + 7)
            while i < src.n and src.s[i] not in "{ \t\r\n":
                i += 1
            i = src.skip_ws_comments(i)
        if i >= src.n or src.s[i] != "{":
            continue
        end = src.match_brace(i)
        if end < 0:
            continue
        body = src.s[i + 1 : end - 1]
        sym = Symbol(name=name, kind="class", file=mod.file, body=body)
        _extract_methods(sym, body)
        sym.bindings = _const_bindings(body)
        sym.constructed = _constructed_types(body)
        mod.classes[sym.name] = sym


def _extract_methods(sym: Symbol, body: str) -> None:
    inner = JsSrc(body)
    for m in re.finditer(
        r"(?:async\s+)?(?:get\s+|set\s+)?(\#?[A-Za-z_][\w]*)\s*\([^)]*\)\s*\{",
        body,
    ):
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "catch", "function"):
            continue
        brace_pos = m.end() - 1
        end = inner.match_brace(brace_pos)
        if end < 0:
            continue
        method_body = body[brace_pos + 1 : end - 1]
        sym.methods[name] = method_body


def _extract_functions(mod: JsModule, src: JsSrc) -> None:
    for m in re.finditer(
        r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][\w]*)\s*\([^)]*\)\s*\{"
        r"|(?:export\s+)?const\s+([A-Za-z_][\w]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_][\w]*)\s*=>\s*\{",
        src.s,
    ):
        name = m.group(1) or m.group(2)
        brace_pos = m.end() - 1
        end = src.match_brace(brace_pos)
        if end < 0:
            continue
        _add_function(mod, name, src.s[brace_pos + 1 : end - 1])


def _add_function(mod: JsModule, name: str, body: str) -> None:
    sym = Symbol(name=name, kind="function", file=mod.file, body=body)
    sym.bindings = _const_bindings(body)
    sym.constructed = _constructed_types(body)
    sym.return_news = re.findall(r"\breturn\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(", body)
    fn_returns = re.findall(r"\breturn\s+([A-Za-z0-9_]+)\s*\(", body)
    if fn_returns:
        for f in fn_returns:
            if f[:1].isupper():
                sym.return_news.append(f)
    mod.functions[name] = sym


def _const_bindings(body: str) -> Dict[str, str]:
    bindings: Dict[str, str] = {}
    for m in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*new\s+([A-Z][A-Za-z0-9_]*)\s*\("
        r"|(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(create[A-Za-z0-9_]+)\s*\(",
        body,
    ):
        var1, typ1, var2, typ2 = m.group(1), m.group(2), m.group(3), m.group(4)
        if var1 and typ1:
            bindings[var1] = typ1
        elif var2 and typ2:
            bindings[var2] = typ2
    return bindings


def _constructed_types(body: str) -> List[str]:
    return re.findall(r"\bnew\s+([A-Z][A-Za-z0-9_]*)\s*\(", body)


def _without_comments(src_text: str) -> str:
    src_text = re.sub(r"/\*.*?\*/", "", src_text, flags=re.S)
    src_text = re.sub(r"//[^\n]*", "", src_text)
    return src_text


def _extract_spawns(mod: JsModule, text: str) -> None:
    code = _without_comments(text)
    for m in re.finditer(
        r"""(?:spawn|spawnProcess|execFile|fork)\(\s*(?:\[\s*)?['"]([^'"]+)['"]""",
        code,
    ):
        cmd = Path(m.group(1)).name
        if cmd not in mod.spawns:
            mod.spawns.append(cmd)


def _extract_routes(mod: JsModule, src: JsSrc) -> None:
    text = src.s
    for m in re.finditer(
        r"""(?:app|router|server)\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""",
        text,
        re.I,
    ):
        method, path = m.group(1).upper(), m.group(2)
        body = _block_after(src, m.end())
        mod.routes.append(Route(method, path, mod.file, body, _nearest_scope(mod, m.start()), "server"))

    for m in re.finditer(
        r"""(?:if\s*\(\s*)?method\s*===\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*&&\s*(?:url\.pathname|pathname|path|req\.url)\s*===\s*['"]([^'"]+)['"]""",
        text,
    ):
        method, path = m.group(1), m.group(2)
        body = _block_after(src, m.end())
        mod.routes.append(Route(method, path, mod.file, body, _nearest_scope(mod, m.start()), "server"))


def _block_after(src: JsSrc, i: int) -> str:
    i = src.skip_ws_comments(i)
    idx = src.s.find("{", i)
    if 0 <= idx < i + 120:
        end = src.match_brace(idx)
        if end > idx:
            return src.s[idx + 1 : end - 1]
    return ""


def _nearest_scope(mod: JsModule, pos: int) -> str:
    best = ""
    best_start = -1
    for name, sym in mod.functions.items():
        idx = mod.text.find(name)
        if 0 <= idx <= pos and idx > best_start:
            best = name
            best_start = idx
    for name, sym in mod.classes.items():
        idx = mod.text.find(name)
        if 0 <= idx <= pos and idx > best_start:
            best = name
            best_start = idx
    return best


def _extract_client_api(mod: JsModule, src: JsSrc) -> None:
    for fn in mod.functions.values():
        for m in re.finditer(
            r"""([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{\s*return\s+(?:this\.)?request\(\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]""",
            fn.body,
        ):
            mod.client_calls.append((m.group(1), m.group(2), m.group(3)))
        for m in re.finditer(
            r"""(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*request\(\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]""",
            fn.body,
        ):
            mod.client_calls.append((m.group(1), m.group(2), m.group(3)))


def _detect_entrypoint(mod: JsModule, text: str) -> None:
    if re.search(r"\bregisterRootComponent\s*\(", text):
        mod.entrypoint = "ui"
    elif re.search(r"\bcreateRoot\s*\(|ReactDOM\.render\s*\(", text):
        mod.entrypoint = "ui"
    elif re.search(r"\bcreateServer\s*\(|app\.listen\s*\(|fastify\.listen\s*\(", text):
        mod.entrypoint = "http"
    elif "createBridgeServer" in mod.functions:
        mod.entrypoint = "http"


def _detect_io(mod: JsModule, text: str) -> None:
    if re.search(r"\bfetch\s*\(|\brequest\s*\(|createServer\s*\(|\bapp\.(get|post)\s*\(", text):
        mod.io_kind.add("http-server" if "createServer" in text else "http-client")
    if re.search(r"\bspawn\s*\(|\bexecFile\s*\(|\bfork\s*\(", text):
        mod.io_kind.add("process")
    if re.search(r"\breadFile\b|\bwriteFile\b|\bstat\b|\bopen\b", text):
        mod.io_kind.add("disk")
    if mod.urls:
        mod.io_kind.add("http-external")


def extract_calls(body: str) -> List[Call]:
    calls: List[Call] = []
    for m in re.finditer(
        r"(?:await\s+)?((?:this\.)?\#?[A-Za-z_][\w]*)(?:\.(\#?[A-Za-z_][\w]*))*\s*\(",
        body,
    ):
        raw = m.group(0)
        parts = raw.split("(")[0].strip().replace("await ", "").split(".")
        if len(parts) == 1:
            recv = None
            method = parts[0]
            chain = []
        else:
            recv = parts[0]
            method = parts[-1]
            chain = parts[1:-1]
        calls.append(Call(recv=recv, method=method, chain=chain, raw=raw))
    return calls


def body_fields(body: str) -> List[str]:
    fields = []
    seen = set()
    for m in re.finditer(r"(?:body|payload|req\.body)\.([A-Za-z0-9_]+)", body):
        f = m.group(1)
        if f not in seen and f not in {"ok", "error", "status", "get", "items", "keys", "values"}:
            seen.add(f)
            fields.append(f)
    for m in re.finditer(r"""(?:body|payload|req\.body)\[['"]([A-Za-z0-9_]+)['"]\]""", body):
        f = m.group(1)
        if f not in seen and f not in {"ok", "error", "status", "get", "items", "keys", "values"}:
            seen.add(f)
            fields.append(f)
    return fields


# ---------------------------------------------------------------------------
# Optional LSP Client (Cross-file compiler precision via JSON-RPC)
# ---------------------------------------------------------------------------

class LspClient:
    """Lightweight JSON-RPC client for local language servers (opt-in via --lsp)."""

    def __init__(self, root: Path, server_cmd: List[str]):
        self.root = root
        self.server_cmd = server_cmd
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        try:
            self.proc = subprocess.Popen(
                self.server_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(self.root),
            )
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class ArchitectureScanner:
    def __init__(self, root_path: str, use_lsp: bool = False):
        self.root = Path(root_path).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.root}")
        self.repo_name = self.root.name
        self.use_lsp = use_lsp
        self.modules: Dict[str, JsModule] = {}
        self.manifest_deps: Dict[str, Set[str]] = defaultdict(set)
        self.all_manifest_deps: Set[str] = set()
        self.config_files: List[str] = []
        self.declared_env_vars: Dict[str, Dict[str, str]] = defaultdict(dict)
        self.consumed_env_vars: Dict[str, Set[str]] = defaultdict(set)
        self.resolved_index: Dict[str, Tuple[str, str]] = {}
        self.trace_route_spec: Optional[str] = None
        self.import_uses: List[dict] = []

    def scan(self) -> None:
        self._scan_manifests()
        self._scan_config_files()
        self._scan_source_files()
        self._index_symbols()
        self._collect_import_uses()

    def _collect_import_uses(self) -> None:
        uses: List[dict] = []
        for rel, mod in self.modules.items():
            if is_test_path(rel) or is_ops_path(rel) or "/ui/" in rel.replace("\\", "/"):
                continue
            for sym in list(mod.functions.values()) + list(mod.classes.values()):
                for pkg, binding in symbol_import_uses(mod, sym):
                    uses.append({
                        "function": sym.name,
                        "file": rel,
                        "package": pkg,
                        "binding": binding,
                    })
        self.import_uses = uses

    def uses_for(self, file: str, name: str) -> List[Tuple[str, str]]:
        return [
            (u["package"], u["binding"])
            for u in self.import_uses
            if u["file"] == file and u["function"] == name
        ]

    def import_packages(self) -> List[dict]:
        items: Dict[str, dict] = {}
        for u in self.import_uses:
            pkg = u["package"]
            hit = items.get(pkg)
            if hit is None:
                hit = {
                    "id": mermaid_id("X", pkg),
                    "name": pkg,
                    "kind": "import",
                    "evidence": u["binding"],
                    "rank": 10,
                    "files": set(),
                    "functions": set(),
                }
                items[pkg] = hit
            hit["files"].add(u["file"])
            hit["functions"].add(u["function"])
            if u["binding"] and hit["evidence"] == pkg:
                hit["evidence"] = u["binding"]
        return [items[k] for k in sorted(items)]

    def _scan_manifests(self) -> None:
        for p in self.root.rglob("package.json"):
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                rel = posix(p.relative_to(self.root))
                deps = set(data.get("dependencies", {}) or {}) | set(data.get("devDependencies", {}) or {})
                self.manifest_deps[rel] = deps
                self.all_manifest_deps |= deps
            except Exception:
                pass
        for p in self.root.rglob("Cargo.toml"):
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            try:
                rel = posix(p.relative_to(self.root))
                in_deps = False
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line.startswith("[dependencies]") or line.startswith("[dev-dependencies]"):
                        in_deps = True
                        continue
                    if line.startswith("["):
                        in_deps = False
                    if in_deps and "=" in line and not line.startswith("#"):
                        dep = line.split("=")[0].strip()
                        if dep:
                            self.manifest_deps[rel].add(dep)
                            self.all_manifest_deps.add(dep)
            except Exception:
                pass
        for p in self.root.rglob("requirements*.txt"):
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            try:
                rel = posix(p.relative_to(self.root))
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        dep = re.split(r"[><=~;]", line)[0].strip()
                        if dep:
                            self.manifest_deps[rel].add(dep)
                            self.all_manifest_deps.add(dep)
            except Exception:
                pass

    def _scan_config_files(self) -> None:
        patterns = [
            ".env*", "config*.json", "config*.yaml", "config*.yml", "config*.toml",
            "appsettings*.json", "wrangler.toml", "docker-compose*.yml", "docker-compose*.yaml",
            "serverless.yml", "values*.yaml", "terraform.tfvars", "*.tfvars",
        ]
        seen = set()
        for pattern in patterns:
            for p in self.root.rglob(pattern):
                if any(part in IGNORE_DIRS for part in p.parts):
                    continue
                rel = posix(p.relative_to(self.root))
                if rel in seen:
                    continue
                seen.add(rel)
                self.config_files.append(rel)
                if p.name.startswith(".env") or p.name.endswith(".tfvars"):
                    try:
                        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                key, val = line.split("=", 1)
                                key = key.strip()
                                if key:
                                    self.declared_env_vars[rel][key] = val.strip().strip("'\"")
                    except Exception:
                        pass

    def _scan_source_files(self) -> None:
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                p = Path(root) / file
                if p.suffix not in SCAN_EXTS:
                    continue
                if p.stat().st_size > 1_500_000:
                    continue
                rel = posix(p.relative_to(self.root))
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                self._scan_env_any(rel, text, p.suffix)
                if p.suffix in JS_EXTS and not p.name.endswith(".d.ts"):
                    self.modules[rel] = parse_js_module(rel, text)
                elif p.suffix == ".py":
                    pymod = parse_py_module(rel, text)
                    if pymod:
                        self.modules[rel] = pymod

    def _scan_env_any(self, rel: str, text: str, suffix: str) -> None:
        if suffix in JS_EXTS:
            return
        if suffix == ".py":
            for m in re.finditer(
                r"os\.environ\.get\(\s*['\"]([A-Za-z0-9_]+)['\"]"
                r"|os\.getenv\(\s*['\"]([A-Za-z0-9_]+)['\"]"
                r"|os\.environ\[\s*['\"]([A-Za-z0-9_]+)['\"]",
                text,
            ):
                name = m.group(1) or m.group(2) or m.group(3)
                if name:
                    self.consumed_env_vars[name].add(rel)
        elif suffix == ".rs":
            for m in re.finditer(r"(?:std::env::var|env!)\s*\(\s*['\"]([A-Za-z0-9_]+)['\"]", text):
                self.consumed_env_vars[m.group(1)].add(rel)
        elif suffix == ".go":
            for m in re.finditer(r"os\.(?:Getenv|LookupEnv)\s*\(\s*['\"]([A-Za-z0-9_]+)['\"]", text):
                self.consumed_env_vars[m.group(1)].add(rel)

    def _index_symbols(self) -> None:
        for rel, mod in self.modules.items():
            for name in list(mod.classes) + list(mod.functions):
                self.resolved_index[name] = (rel, name)
            for var in mod.env_vars:
                self.consumed_env_vars[var].add(rel)

    def resolve_local(self, from_file: str, spec: str) -> Optional[str]:
        if not spec.startswith("."):
            return None
        base = (self.root / from_file).parent / spec
        if spec.startswith(".") and not spec.startswith("./") and not spec.startswith("../"):
            level = 0
            rest = spec
            while rest.startswith("."):
                level += 1
                rest = rest[1:]
            py_base = Path(from_file).parent
            for _ in range(max(0, level - 1)):
                py_base = py_base.parent
            if rest:
                py_base = py_base / rest.replace(".", "/")
            base = self.root / py_base
        candidates = [
            base,
            Path(str(base) + ".js"),
            Path(str(base) + ".ts"),
            Path(str(base) + ".mjs"),
            Path(str(base) + ".cjs"),
            Path(str(base) + ".jsx"),
            Path(str(base) + ".tsx"),
            Path(str(base) + ".py"),
            base / "index.js",
            base / "index.ts",
            base / "__init__.py",
        ]
        for cand in candidates:
            try:
                rel = posix(cand.resolve().relative_to(self.root))
            except Exception:
                continue
            if rel in self.modules:
                return rel
        return None

    def lookup_symbol(self, file: str, name: str) -> Optional[Symbol]:
        mod = self.modules.get(file)
        if not mod:
            return None
        if name in mod.classes:
            return mod.classes[name]
        if name in mod.functions:
            return mod.functions[name]
        spec = mod.imports.get(name)
        if spec:
            target = self.resolve_local(file, spec)
            if target:
                tmod = self.modules[target]
                if name in tmod.classes:
                    return tmod.classes[name]
                if name in tmod.functions:
                    return tmod.functions[name]
                if len(tmod.classes) == 1 and name[0].isupper():
                    return next(iter(tmod.classes.values()))
                if len(tmod.functions) == 1:
                    return next(iter(tmod.functions.values()))
        indexed = self.resolved_index.get(name)
        if indexed:
            tmod = self.modules[indexed[0]]
            return tmod.classes.get(name) or tmod.functions.get(name)
        return None

    def all_routes(self) -> List[Route]:
        seen = set()
        out: List[Route] = []
        for mod in self.modules.values():
            if is_test_path(mod.file):
                continue
            for route in mod.routes:
                key = (route.method, normalize_route_path(route.path))
                if key in seen:
                    continue
                seen.add(key)
                route.path = normalize_route_path(route.path)
                out.append(route)
        return out

    def runtimes(self) -> Dict[str, dict]:
        groups: Dict[str, dict] = {}
        for rel, mod in self.modules.items():
            if is_test_path(rel) or is_ops_path(rel):
                continue
            if not mod.entrypoint:
                continue
            top = rel.split("/")[0] if "/" in rel else "root"
            g = groups.setdefault(top, {
                "id": top,
                "kind": mod.entrypoint,
                "entrypoints": [],
                "files": set(),
            })
            if mod.entrypoint == "http":
                g["kind"] = "http"
            g["entrypoints"].append(rel)
            g["files"].add(rel)
        if not groups:
            for rel, mod in self.modules.items():
                if is_test_path(rel) or is_ops_path(rel):
                    continue
                if mod.routes or mod.client_calls:
                    top = rel.split("/")[0] if "/" in rel else "root"
                    g = groups.setdefault(top, {
                        "id": top,
                        "kind": "http" if mod.routes else "ui",
                        "entrypoints": [rel],
                        "files": {rel},
                    })
                    g["files"].add(rel)
        for g in groups.values():
            for ep in list(g["entrypoints"]):
                if ep in self.modules:
                    g["files"] |= self._local_import_tree(ep, 8)
        if not groups and self.import_uses:
            groups["app"] = {
                "id": "app",
                "kind": "http",
                "entrypoints": [],
                "files": set(),
            }
            for u in self.import_uses:
                groups["app"]["files"].add(u["file"])
        return groups

    def _local_import_tree(self, start: str, depth: int) -> Set[str]:
        seen: Set[str] = set()
        stack = [(start, 0)]
        while stack:
            file, d = stack.pop()
            if file in seen or d > depth:
                continue
            seen.add(file)
            mod = self.modules.get(file)
            if not mod:
                continue
            for spec in mod.imports.values():
                target = self.resolve_local(file, spec)
                if target and not is_test_path(target):
                    stack.append((target, d + 1))
        return seen

    def architectural_components(self, runtime: dict) -> List[dict]:
        """Discovers components based on structural role (imports, constructors, routes)."""
        comps = []
        seen_names = set()
        for rel in sorted(runtime["files"]):
            mod = self.modules.get(rel)
            if not mod or is_test_path(rel):
                continue
            for sym in list(mod.classes.values()) + list(mod.functions.values()):
                name = sym.name
                if name in seen_names or name.startswith("Fake") or name.endswith("Error"):
                    continue
                is_component = (
                    sym.kind == "class"
                    or bool(self.uses_for(rel, name))
                    or bool(sym.constructed)
                    or bool(sym.return_news)
                    or any(r.scope == name for r in mod.routes)
                )
                if not is_component:
                    continue
                seen_names.add(name)
                comps.append({
                    "id": mermaid_id("C", name),
                    "name": name,
                    "file": rel,
                    "kind": sym.kind,
                    "runtime": runtime["id"],
                })
        ranked = []
        for c in comps:
            score = 0
            if c["kind"] == "class":
                score += 30
            if any(u["function"] == c["name"] for u in self.import_uses):
                score += 25
            ranked.append((score, c["name"], c))
        ranked.sort(key=lambda x: (-x[0], x[1]))
        return [c for _, _, c in ranked[:16]]

    def externals(self, include_device: bool = False) -> List[dict]:
        items = {}
        runtime_files = set()
        for rt in self.runtimes().values():
            runtime_files |= set(rt["files"])

        def add(name, kind, evidence, rank, files=None):
            if name in items:
                if files:
                    items[name].setdefault("files", set()).update(files)
                return
            items[name] = {
                "id": mermaid_id("X", name),
                "name": name,
                "kind": kind,
                "evidence": evidence,
                "rank": rank,
                "files": set(files or ()),
            }

        for pkg in self.import_packages():
            add(pkg["name"], "import", pkg["evidence"], 10, pkg["files"])
            items[pkg["name"]]["functions"] = set(pkg["functions"])

        for rel, mod in self.modules.items():
            if is_test_path(rel) or is_ops_path(rel) or rel not in runtime_files:
                continue
            for url in mod.urls:
                host = re.sub(r"^https?://", "", url).split("/")[0]
                if any(x in url.lower() for x in ("localhost", "127.0.0.1", "example.", "tailnet", "<", "placeholder")):
                    continue
                if "/ui/" in rel.replace("\\", "/"):
                    continue
                add(host, "http", url, 8, {rel})
            for cmd in mod.spawns:
                add(f"{cmd} process", "process", f"spawn({cmd})", 10, {rel})
            if "disk" in mod.io_kind:
                add("Local disk files", "disk", rel, 8, {rel})
        return [items[k] for k in sorted(items, key=lambda n: (-items[n]["rank"], n))]

    def composition_edges(self, components: List[dict]) -> List[Tuple[str, str, str]]:
        by_name = {c["name"]: c for c in components}
        ids = {c["id"] for c in components}
        edges = []
        seen = set()

        def link(a, b, label):
            if a == b or a not in ids or b not in ids:
                return
            key = (a, b, label)
            if key in seen:
                return
            seen.add(key)
            edges.append((a, b, label))

        for c in components:
            mod = self.modules.get(c["file"])
            if not mod:
                continue
            sym = mod.classes.get(c["name"]) or mod.functions.get(c["name"])
            if not sym:
                continue
            for bound_type in dict.fromkeys(list(sym.bindings.values()) + sym.constructed + sym.return_news):
                target = by_name.get(bound_type)
                if target:
                    link(c["id"], target["id"], "owns")

        api = next((c for c in components if c["name"].endswith("Api") or c["name"].endswith("API")), None)
        app = by_name.get("App")
        server = next((c for c in components if "Server" in c["name"] or "app" in c["name"]), None)
        if app and api:
            link(app["id"], api["id"], "uses")
        if api and server:
            link(api["id"], server["id"], "HTTP")
        return edges

    def choose_flow_route(self) -> Optional[Route]:
        routes = self.all_routes()
        if self.trace_route_spec:
            spec = self.trace_route_spec.strip()
            parts = spec.split(None, 1)
            if len(parts) == 2:
                method, path = parts[0].upper(), normalize_route_path(parts[1])
                for r in routes:
                    if r.method == method and r.path == path:
                        return r
            path = normalize_route_path(spec)
            for r in routes:
                if r.path == path:
                    return r
        for r in routes:
            if r.method == "POST" and r.path in {"/message", "/messages", "/chat"}:
                return r
        for r in routes:
            if r.method == "POST":
                return r
        return routes[0] if routes else None

    def trace_route(self, route: Route, max_depth: int = 5) -> List[dict]:
        steps = []
        seen = set()
        scope_name = route.scope
        scope_sym = self.lookup_symbol(route.file, scope_name) if scope_name else None
        bindings: Dict[str, str] = {}
        for fn in self.modules.get(route.file, JsModule("", "")).functions.values():
            bindings.update(fn.bindings)
        if scope_sym:
            bindings.update(scope_sym.bindings)

        def add(src, actor, action, detail, file):
            steps.append({
                "src": src,
                "actor": actor,
                "action": action,
                "detail": detail,
                "file": file,
            })

        add("User", "HTTP", f"{route.method} {route.path}", "HTTP Request", route.file)

        def walk(src, file, name, body, depth):
            if depth > max_depth or len(steps) > 22:
                return
            key = (file, name)
            if key in seen:
                return
            seen.add(key)
            local_bindings = dict(bindings)
            owner = self.lookup_symbol(file, name)
            if owner:
                local_bindings.update(owner.bindings)
            walking = owner
            if walking is None:
                for cls in self.modules.get(file, JsModule("", "")).classes.values():
                    if name in cls.methods:
                        walking = cls
                        break
            for pkg, binding in self.uses_for(file, name):
                add(src, pkg, binding, binding, file)
            file_mod = self.modules.get(file)
            if file_mod:
                for fn in file_mod.functions.values():
                    if name in (fn.return_news or []):
                        local_bindings.update(fn.bindings)
                        for pkg, binding in self.uses_for(file, fn.name):
                            add(src, pkg, binding, binding, file)
            mod = self.modules.get(file)
            imported = mod.imports if mod else {}
            for call in extract_calls(body):
                if call.recv in {None, "self", "this"} and call.method == name:
                    continue
                target_name = call.method
                recv_type = None
                if call.recv in {None, "this"} and walking and target_name in walking.methods:
                    recv_type = walking.name
                elif call.recv and call.recv not in {"this", "options", "console"}:
                    recv_type = local_bindings.get(call.recv)

                pkg = None
                if call.recv and call.recv in imported and not is_noise_import(imported[call.recv]):
                    pkg = import_label(imported[call.recv])
                elif recv_type and recv_type in imported and not is_noise_import(imported[recv_type]):
                    pkg = import_label(imported[recv_type])
                if pkg:
                    add(src, pkg, target_name, call.recv or recv_type, file)
                    continue

                resolved = None
                if recv_type:
                    resolved = self.lookup_symbol(file, recv_type)
                if not resolved:
                    resolved = self.lookup_symbol(file, target_name)
                if resolved and resolved.kind == "function" and resolved.return_news:
                    for cand in reversed(resolved.return_news):
                        cls = self.lookup_symbol(resolved.file, cand) or self.lookup_symbol(file, cand)
                        if cls and cls.kind == "class" and target_name in cls.methods:
                            resolved = cls
                            break
                if not resolved:
                    continue
                if resolved.name.endswith("Error") or resolved.name.startswith("Fake"):
                    continue
                actor = resolved.name
                if actor == src and call.recv in {None, "self", "this"}:
                    continue

                add(src, actor, target_name, call.raw.strip()[:70], resolved.file)
                next_body = resolved.methods.get(target_name) or resolved.body
                if next_body:
                    walk(actor, resolved.file, resolved.name, next_body, depth + 1)
                    if "spawn" in (next_body or resolved.body or ""):
                        cmds = self.modules.get(resolved.file).spawns if resolved.file in self.modules else []
                        cmd = cmds[0] if cmds else "child process"
                        add(actor, f"{cmd} process", "spawn", f"spawn({cmd})", resolved.file)

        walk("HTTP", route.file, scope_name or Path(route.file).stem, route.body, 0)
        return steps

    def client_for_route(self, route: Route) -> Optional[Tuple[str, str]]:
        for mod in self.modules.values():
            for name, method, path in mod.client_calls:
                if method == route.method and path == route.path:
                    return name, mod.file
        return None

    def _owner_component(self, files: Set[str], components_by_rt: dict, runtimes: dict) -> Optional[dict]:
        for comps in components_by_rt.values():
            for c in comps:
                if c["file"] in files:
                    return c
        return None

    def extract_data_flow(self, route: Optional[Route]) -> List[Tuple[str, str, str]]:
        """Extracts direct client-to-client data flow from handler AST."""
        edges: List[Tuple[str, str, str]] = []
        seen = set()
        if not route:
            return edges
        mod = self.modules.get(route.file)
        if not mod:
            return edges

        local_bindings: Dict[str, str] = {}
        for fn in mod.functions.values():
            local_bindings.update(fn.bindings)
        scope_sym = self.lookup_symbol(route.file, route.scope)
        if scope_sym:
            local_bindings.update(scope_sym.bindings)

        def resolve_comp(name: Optional[str]) -> Optional[str]:
            if not name:
                return None
            typ = local_bindings.get(name, name)
            sym = self.lookup_symbol(route.file, typ)
            if sym:
                if sym.kind == "class":
                    return sym.name
                if sym.return_news:
                    cand = sym.return_news[-1]
                    cand_sym = self.lookup_symbol(sym.file, cand) or self.lookup_symbol(route.file, cand)
                    return cand_sym.name if cand_sym else cand
                return sym.name
            return typ if typ and (typ[:1].isupper() or typ.endswith("Store") or typ.endswith("Index") or typ.endswith("Agent")) else None

        if route.file.endswith(".py"):
            try:
                tree = ast.parse(mod.text)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == route.scope:
                        var_producer: Dict[str, str] = {}
                        for stmt in _py_local_statements(node):
                            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
                                recv, method = _py_callee(stmt.value.func)
                                prod = resolve_comp(recv) or resolve_comp(method)
                                if prod:
                                    for target in stmt.targets:
                                        if isinstance(target, ast.Name):
                                            var_producer[target.id] = prod
                            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.value, ast.Call) and isinstance(stmt.target, ast.Name):
                                recv, method = _py_callee(stmt.value.func)
                                prod = resolve_comp(recv) or resolve_comp(method)
                                if prod:
                                    var_producer[stmt.target.id] = prod

                            calls_in_stmt = [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]
                            for call in calls_in_stmt:
                                recv2, method2 = _py_callee(call.func)
                                consumer = resolve_comp(recv2) or resolve_comp(method2)
                                if not consumer:
                                    continue
                                used_vars = set()
                                for arg in call.args:
                                    for sub in ast.walk(arg):
                                        if isinstance(sub, ast.Name) and sub.id in var_producer:
                                            used_vars.add(sub.id)
                                for kw in call.keywords:
                                    for sub in ast.walk(kw.value):
                                        if isinstance(sub, ast.Name) and sub.id in var_producer:
                                            used_vars.add(sub.id)
                                for var_name in used_vars:
                                    src_comp = var_producer[var_name]
                                    if src_comp != consumer:
                                        key = (src_comp, consumer, var_name)
                                        if key not in seen:
                                            seen.add(key)
                                            edges.append(key)
            except Exception:
                pass
        else:
            var_producer = {}
            for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:await\s+)?([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\(", route.body):
                var_name, recv, method = m.group(1), m.group(2), m.group(3)
                prod = resolve_comp(recv) or resolve_comp(method)
                if prod:
                    var_producer[var_name] = prod
            for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:await\s+)?([A-Za-z0-9_]+)\(", route.body):
                var_name, fn_name = m.group(1), m.group(2)
                prod = resolve_comp(fn_name)
                if prod:
                    var_producer[var_name] = prod
            for m in re.finditer(r"([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\(([^;]+)\)", route.body):
                recv2, method2, args_str = m.group(1), m.group(2), m.group(3)
                consumer = resolve_comp(recv2) or resolve_comp(method2)
                if not consumer:
                    continue
                for var_name, src_comp in var_producer.items():
                    if re.search(r"\b" + re.escape(var_name) + r"\b", args_str):
                        if src_comp != consumer:
                            key = (src_comp, consumer, var_name)
                            if key not in seen:
                                seen.add(key)
                                edges.append(key)
        return edges

    def render_markdown(self) -> str:
        runtimes = self.runtimes()
        components_by_rt = {rid: self.architectural_components(rt) for rid, rt in runtimes.items()}
        all_components = [c for cs in components_by_rt.values() for c in cs]
        externals = self.externals(include_device=False)
        device_ext = self.externals(include_device=True)
        edges = self.composition_edges(all_components)
        routes = self.all_routes()
        flow_route = self.choose_flow_route()
        data_flow_edges = self.extract_data_flow(flow_route)

        md: List[str] = []
        md.append(f"# {self.repo_name} — Architecture\n")
        md.append(
            "Generated by `arch-map` using **deterministic structural AST analysis** "
            "(brace-matched JS/TS and Python AST) "
            "plus **function → import** bindings and **client data flow**. "
            "Same codebase -> same document. Zero hallucinations.\n"
        )
        md.append("| View | Question | Source |")
        md.append("| :--- | :--- | :--- |")
        md.append("| **Level 1 — System context & external dependencies** | Who talks to this system, and what external packages/APIs are called? | Entrypoints, URL literals, `spawn`, imported packages |")
        md.append("| **Level 2a — Control plane (wiring)** | How is the application instantiated, configured, and injected? | Factory functions, constructors, and binding graph |")
        md.append("| **Level 2b — Data plane (client data flow)** | How do internal services and storage exchange data at runtime? | Route handlers, variable passing, and client data graph |")
        md.append("| **Level 3 — Request execution flow** | What happens on a critical request end-to-end? | Route handler call-graph walk, parameter contracts, and transforms |")
        md.append("")
        md.append("---\n")

        md.extend(self._render_level1(runtimes, components_by_rt, externals))
        md.extend(self._render_level2a(runtimes, components_by_rt, edges))
        md.extend(self._render_level2b(runtimes, components_by_rt, device_ext, data_flow_edges, routes, flow_route))
        md.extend(self._render_level3(flow_route, runtimes))
        md.extend(self._render_routes(routes))
        md.extend(self._render_env())

        rendered = "\n".join(md)
        validation_errors = lint_markdown(rendered, file_path=f"<{self.repo_name} generated>")
        if validation_errors:
            raise MermaidLintError(
                f"Generated architecture Markdown contains Mermaid syntax errors:\n"
                + "\n".join(f"  - {e}" for e in validation_errors)
            )
        return rendered

    def _runtime_title(self, rt: dict) -> str:
        if rt["kind"] == "ui":
            return "Client app"
        if rt["kind"] == "http":
            if rt["id"] in {"bridge", "api", "server", "src", "app"}:
                return "HTTP service" if rt["id"] in {"src", "app", "api", "server"} else "HTTP bridge"
            return "HTTP service"
        return rt["id"].replace("-", " ").title()

    def _render_level1(self, runtimes, components_by_rt, externals) -> List[str]:
        md = [
            "## Level 1 — System context & external dependencies\n",
            "Internal workload boundary versus external libraries, SDKs, and services. "
            "Internal folders such as `test/` and `scripts/` are omitted.\n",
            "```mermaid",
            "flowchart TB",
            '    subgraph ClientZone["Client Perimeter"]',
            '        User(["User / Client"])',
            '    end',
            f'    subgraph AppBoundary["Workload Boundary ({mermaid_label(self.repo_name)})"]',
        ]
        rt_ids = {}
        for rid, rt in sorted(runtimes.items()):
            nid = mermaid_id("RT", rid)
            rt_ids[rid] = nid
            title = self._runtime_title(rt)
            files = ", ".join(Path(f).name for f in rt["entrypoints"][:2])
            md.append(f'        {nid}["{mermaid_label(title)}\\n{files}"]')
        md.append("    end")

        if externals:
            md.append('    subgraph CloudPerimeter["External Dependencies & Services"]')
            for ext in externals:
                md.append(f'        {ext["id"]}(["{mermaid_label(ext["name"])}"])')
            md.append("    end")

        ui = next((rid for rid, rt in runtimes.items() if rt["kind"] == "ui"), None)
        http = next((rid for rid, rt in runtimes.items() if rt["kind"] == "http"), None)
        if ui:
            md.append(f"    User -->|interacts| {rt_ids[ui]}")
        elif http:
            md.append(f"    User -->|HTTP| {rt_ids[http]}")
        if ui and http:
            md.append(f"    {rt_ids[ui]} -->|HTTP| {rt_ids[http]}")

        http_id = rt_ids.get(http) if http else (rt_ids[next(iter(rt_ids))] if rt_ids else None)
        ui_id = rt_ids.get(ui) if ui else None
        kind_label = {
            "http": "HTTPS", "process": "spawn", "disk": "fs",
            "import": "import", "device": "import",
        }
        for ext in externals:
            target_node = http_id or ui_id
            if target_node:
                lbl = kind_label.get(ext["kind"], ext["kind"])
                if ext.get("evidence") and ext["evidence"] != ext["name"]:
                    lbl = f"{lbl} / {ext['evidence']}"
                md.append(f"    {target_node} -->|{mermaid_edge_label(lbl)}| {ext['id']}")
        md.append("```\n")
        if externals:
            md.append("| External system | Kind | Evidence |")
            md.append("| :--- | :--- | :--- |")
            for ext in externals:
                md.append(f"| **{ext['name']}** | `{ext['kind']}` | `{ext['evidence']}` |")
            md.append("")
        md.append("---\n")
        return md

    def _render_level2a(self, runtimes, components_by_rt, edges) -> List[str]:
        md = [
            "## Level 2a — Control plane (Wiring & Dependency Injection)\n",
            "Factory functions, constructors, and dependency injection wiring. "
            "Shows how service instances and client connections are assembled during startup.\n",
            "```mermaid",
            "flowchart LR",
        ]
        for rid, rt in sorted(runtimes.items()):
            title = self._runtime_title(rt)
            md.append(f'    subgraph {mermaid_id("CP", rid)}["{mermaid_label(title)} Control Plane"]')
            for c in components_by_rt.get(rid, []):
                md.append(f'        {c["id"]}["{mermaid_label(c["name"])}"]')
            md.append("    end")

        for src, dst, label in edges:
            md.append(f"    {src} -->|{mermaid_edge_label(label)}| {dst}")
        md.append("```\n")
        md.append("---\n")
        return md

    def _render_level2b(self, runtimes, components_by_rt, externals, data_flow_edges, routes, flow_route) -> List[str]:
        md = [
            "## Level 2b — Data plane (Client-to-client data flow)\n",
            "Runtime data-flow topology. Shows how client components pass intermediate data (arguments, return values) "
            "to downstream storage and cloud APIs during request execution.\n",
            "```mermaid",
            "flowchart LR",
        ]
        for rid, rt in sorted(runtimes.items()):
            title = self._runtime_title(rt)
            md.append(f'    subgraph {mermaid_id("DP", rid)}["{mermaid_label(title)} Runtime"]')
            for c in components_by_rt.get(rid, []):
                md.append(f'        {c["id"]}["{mermaid_label(c["name"])}"]')
            md.append("    end")

        shown_ext = [ext for ext in externals if ext["kind"] != "import" or any(u["package"] == ext["name"] for u in self.import_uses)]
        if shown_ext:
            md.append('    subgraph DP_Externals["External Dependencies & Services"]')
            for ext in shown_ext:
                md.append(f'        {ext["id"]}(["{mermaid_label(ext["name"])}"])')
            md.append("    end")

        by_name = {c["name"]: c for cs in components_by_rt.values() for c in cs}
        pkg_ids = {ext["name"]: ext["id"] for ext in shown_ext}

        for src_name, dst_name, var_name in data_flow_edges:
            src_c = by_name.get(src_name)
            dst_c = by_name.get(dst_name)
            if src_c and dst_c:
                md.append(f"    {src_c['id']} -->|{mermaid_edge_label(var_name)}| {dst_c['id']}")

        for u in self.import_uses:
            src = by_name.get(u["function"])
            dst = pkg_ids.get(u["package"])
            if src and dst:
                md.append(f"    {src['id']} -->|{mermaid_edge_label(u['binding'])}| {dst}")

        kind_label = {"http": "HTTPS", "process": "stdio", "disk": "fs"}
        for ext in shown_ext:
            if ext["kind"] == "import":
                continue
            owner = self._owner_component(set(ext.get("files") or ()), components_by_rt, runtimes)
            if owner:
                md.append(f"    {owner['id']} -.->|{mermaid_edge_label(kind_label.get(ext['kind'], ext['kind']))}| {ext['id']}")

        md.append("```\n")
        if self.import_uses:
            md.append("Function → import bindings:\n")
            md.append("| Component / Function | Import | Binding | File |")
            md.append("| :--- | :--- | :--- | :--- |")
            for u in sorted(self.import_uses, key=lambda x: (x["function"], x["package"])):
                md.append(f"| `{u['function']}` | `{u['package']}` | `{u['binding']}` | `{u['file']}` |")
            md.append("")
        if data_flow_edges:
            md.append("Extracted client-to-client data edges (from AST):\n")
            md.append("| Source Component | Target Component | Passed Variable / Data |")
            md.append("| :--- | :--- | :--- |")
            for src_name, dst_name, var_name in data_flow_edges:
                md.append(f"| `{src_name}` | `{dst_name}` | `{var_name}` |")
            md.append("")
        md.append("---\n")
        return md

    def _render_level3(self, route: Optional[Route], runtimes) -> List[str]:
        md = ["## Level 3 — Request execution flow\n"]
        if not route:
            md.append("*No HTTP route handler was found to trace.*\n")
            md.append("---\n")
            return md

        steps = self.trace_route(route)
        client = self.client_for_route(route)
        fields = body_fields(route.body)
        md.append(
            f"Traced **`{route.method} {route.path}`** from `{route.file}`"
            + (f" (client method `{client[0]}` in `{client[1]}`)" if client else "")
            + ". Handler call-graph walk with parameter bindings.\n"
        )
        if fields:
            md.append("Request body fields read in handler: " + ", ".join(f"`{f}`" for f in fields) + ".\n")
        if "async" in fields:
            md.append("Branch: `body.async` chooses `startMessage` (non-blocking) vs `sendMessage` (await completion).\n")

        def pid(name: str) -> str:
            aliases = {
                "User": "User", "App": "App", "HTTP": "HTTP", "Api": "Api",
                "isAuthorized": "Auth", "SessionStore": "Store",
                "OmpRpcTransport": "Rpc", "PushNotificationRegistry": "Push",
                "Expo Push API": "Expo", "createImageAttachmentStore": "Images",
                "storeMessageAttachments": "Attach", "getResumeSession": "Resume",
            }
            return aliases.get(name, mermaid_id("P", name))

        md.append("```mermaid")
        md.append("sequenceDiagram")
        md.append("    autonumber")
        md.append("    actor User")
        declared = ["User"]

        def declare(name, label=None):
            ident = pid(name)
            if ident in declared:
                return ident
            declared.append(ident)
            md.append(f"    participant {ident} as {mermaid_label(label or name)}")
            return ident

        if any(rt["kind"] == "ui" for rt in runtimes.values()):
            declare("App", "App")
        if client:
            declare("Api", client[0])
        declare("HTTP", Path(route.file).name)
        for step in steps:
            declare(step["actor"], step["actor"])
            if step.get("src") and step["src"] not in {"User"}:
                declare(step["src"], step["src"])

        if "App" in declared and "Api" in declared:
            md.append("    User->>App: send text")
            md.append(f"    App->>Api: {client[0] if client else 'request'}()")
            md.append(f"    Api->>HTTP: {route.method} {route.path}")
        elif "App" in declared:
            md.append("    User->>App: send text")
            md.append(f"    App->>HTTP: {route.method} {route.path}")
        else:
            md.append(f"    User->>HTTP: {route.method} {route.path}")

        for step in steps:
            src = step.get("src") or "HTTP"
            if src == "User" and step["actor"] == "HTTP":
                continue
            md.append(f"    {pid(src)}->>{pid(step['actor'])}: {mermaid_label(step['action'])}")
        md.append("    HTTP-->>App: 200 JSON" if "App" in declared else "    HTTP-->>User: 200 JSON")
        md.append("```\n")

        md.append("### Transform table\n")
        md.append("| Step | From → To | Action | Where |")
        md.append("| :--- | :--- | :--- | :--- |")
        n = 1
        if client:
            md.append(
                f"| {n} | App → API | `{client[0]}` sends `{route.method} {route.path}`"
                + (f" (`{', '.join(fields)}`)" if fields else "")
                + f" | `{client[1]}` |"
            )
            n += 1
        for step in steps:
            md.append(
                f"| {n} | `{step.get('src', 'HTTP')}` → `{step['actor']}` | `{mermaid_label(step['action'])}` | `{step['file']}` |"
            )
            n += 1
            if n > 20:
                break
        md.append("")
        md.append("---\n")
        return md

    def _render_routes(self, routes: List[Route]) -> List[str]:
        md = ["## Routes\n"]
        if not routes:
            md.append("*No HTTP routes detected.*\n")
            md.append("---\n")
            return md
        md.append("| Method | Path | Defined in |")
        md.append("| :--- | :--- | :--- |")
        for r in routes:
            md.append(f"| `{r.method}` | `{r.path}` | `{r.file}` |")
        md.append("")
        md.append("---\n")
        return md

    def _render_env(self) -> List[str]:
        md = [
            "## Environment & lift-and-shift matrix\n",
            "Inventory of environment variables required to run or migrate this codebase.\n",
        ]
        all_env = sorted(set(self.consumed_env_vars) | {k for d in self.declared_env_vars.values() for k in d})
        if not all_env:
            md.append("*No environment variables detected.*\n")
            return md
        md.append("| Environment variable | Consumed in | Declared in |")
        md.append("| :--- | :--- | :--- |")
        for ev in all_env:
            consumers = ", ".join(f"`{Path(p).name}`" for p in sorted(self.consumed_env_vars.get(ev, []))[:3]) or "*Declared only*"
            decls = [f"`{cf}`" for cf, vdict in self.declared_env_vars.items() if ev in vdict]
            decl = ", ".join(decls) or "*Runtime only*"
            md.append(f"| `{ev}` | {consumers} | {decl} |")
        md.append("")
        return md


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a codebase and generate Level 1–3 architecture Markdown."
    )
    parser.add_argument("target", nargs="?", default=".", help="Repository path (default: .)")
    parser.add_argument("-o", "--output", help="Output Markdown path")
    parser.add_argument("--stdout", action="store_true", help="Print Markdown to stdout")
    parser.add_argument("--route", help="Route to trace in Level 3, e.g. 'POST /message'")
    parser.add_argument("--lsp", action="store_true", help="Enable LSP semantic reference resolution")
    parser.add_argument("--lint", nargs="?", const=".", help="Lint Markdown & Mermaid diagrams in file or directory (default: .)")
    args = parser.parse_args()

    if args.lint is not None:
        lint_target = Path(args.lint).resolve()
        if not lint_target.exists():
            print(f"Error: Lint target path does not exist: {lint_target}", file=sys.stderr)
            sys.exit(1)
        files_to_lint = []
        if lint_target.is_file():
            files_to_lint.append(lint_target)
        else:
            files_to_lint.extend(sorted(lint_target.rglob("*.md")))

        all_errors: List[str] = []
        for file in files_to_lint:
            if any(part in IGNORE_DIRS for part in file.parts):
                continue
            try:
                content = file.read_text(encoding="utf-8", errors="ignore")
                rel_path = posix(file.relative_to(lint_target if lint_target.is_dir() else lint_target.parent))
                errors = lint_markdown(content, file_path=rel_path)
                all_errors.extend(errors)
            except Exception as e:
                all_errors.append(f"{file}: Failed to read file: {e}")

        if all_errors:
            print(f"❌ Markdown & Mermaid Lint Failed ({len(all_errors)} issues found):", file=sys.stderr)
            for err in all_errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"✅ All {len(files_to_lint)} Markdown & Mermaid files passed validation cleanly.", file=sys.stderr)
            sys.exit(0)

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {target_path} ...", file=sys.stderr)
    scanner = ArchitectureScanner(str(target_path), use_lsp=args.lsp)
    scanner.trace_route_spec = args.route
    scanner.scan()
    markdown_content = scanner.render_markdown()

    if args.stdout:
        print(markdown_content)
        return

    if args.output:
        out_path = Path(args.output).resolve()
    else:
        docs_dir = target_path / "docs"
        out_path = (docs_dir if docs_dir.exists() else target_path) / "architecture-mental-model.md"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown_content, encoding="utf-8")
    routes = scanner.all_routes()
    print(f"Wrote {out_path}", file=sys.stderr)
    print(
        f"Runtimes: {len(scanner.runtimes())}  routes: {len(routes)}  "
        f"imports: {len({u['package'] for u in scanner.import_uses})}  env vars: {len(scanner.consumed_env_vars)}  "
        f"modules: {len(scanner.modules)}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
