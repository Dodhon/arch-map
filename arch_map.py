#!/usr/bin/env python3
"""
arch-map: Deterministic architecture scanner.

Produces three views from source structure (brace-matched JS/TS analysis
and Python stdlib AST):
  1. System context
  2. Service / container topology
  3. Request data flow for one route

No language server is used in the default pass. Same repo + same analyzer
version yields the same Markdown.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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

UI_PACKAGES = {
    "react", "react-native", "react-dom", "markdown-it", "expo-status-bar",
    "react-native-markdown-display", "@expo/vector-icons", "expo",
}

DEVICE_IO_PACKAGES = {
    "expo-notifications", "expo-location", "expo-image-picker", "expo-file-system",
    "expo-secure-store", "expo-constants", "expo-device", "expo-application",
    "@react-native-async-storage/async-storage",
}

SKIP_CALL_NAMES = {
    "if", "for", "while", "switch", "catch", "function", "return", "typeof",
    "void", "await", "new", "delete", "throw", "console", "Promise", "Date",
    "Error", "JSON", "Object", "Array", "Math", "Number", "String", "Boolean",
    "Buffer", "Set", "Map", "WeakMap", "WeakSet", "Symbol", "URL", "URLSearchParams",
    "RegExp", "parseInt", "parseFloat", "isNaN", "isFinite", "encodeURIComponent",
    "decodeURIComponent", "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "require", "import", "super",
}

UTIL_NAME_RE = re.compile(
    r"^(create)?(Logger|Id|Hash)?$|^nowIso$|^log$|^devWarn$|^styles$|^theme$",
    re.I,
)

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

AZURE_CORE_PACKAGES = {
    "@azure/core", "@azure/core-rest-pipeline", "@azure/core-auth",
    "@azure/core-client", "@azure/core-tracing", "@azure/core-util",
    "@azure/core-http", "@azure/abort-controller", "@azure/logger",
    "azure-core", "azure-common",
}

def mermaid_id(prefix: str, name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]", "_", str(name)).strip("_")
    if not cleaned:
        cleaned = "x"
    if cleaned[0].isdigit():
        cleaned = "n_" + cleaned
    return f"{prefix}_{cleaned}"[:70]


def mermaid_label(text: str) -> str:
    return str(text).replace('"', "'").replace("\n", " ").strip()[:80]


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


def classify_env(name: str) -> str:
    lower = name.lower()
    if any(x in lower for x in ("token", "secret", "key", "password", "auth", "credential")):
        return "Secret / Token"
    if any(x in lower for x in ("url", "host", "uri", "endpoint", "port", "connection")):
        return "Endpoint / Connection"
    if any(x in lower for x in ("enable", "disable", "flag", "allow", "mode")):
        return "Feature Flag / Mode"
    if any(x in lower for x in ("path", "dir", "root")):
        return "Path / Directory"
    return "Config Setting"



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
    if label in UI_PACKAGES or top in UI_PACKAGES:
        return True
    if label in AZURE_CORE_PACKAGES or spec in AZURE_CORE_PACKAGES:
        return True
    if label.startswith("@azure/core") or label.startswith("azure.core"):
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


def parse_python_imports(text: str) -> Tuple[Set[str], Set[str]]:
    modules: Set[str] = set()
    names: Set[str] = set()
    for m in re.finditer(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+([^\n#]+)", text, re.M):
        modules.add(m.group(1))
        for part in m.group(2).replace("(", " ").replace(")", " ").split(","):
            part = part.strip()
            if not part or part == "*":
                continue
            names.add(part.split(" as ")[-1].strip().split(".")[-1])
    for m in re.finditer(r"^\s*import\s+([A-Za-z_][\w.]*)", text, re.M):
        modules.add(m.group(1))
    return modules, names


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
                    i = self.match_pair(i + 1)
                    continue
                i += 1
            return i
        while i < n:
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == quote:
                return i + 1
            if s[i] in "\n\r" and quote != "`":
                return i
            i += 1
        return i

    def match_pair(self, i: int) -> int:
        s, n = self.s, self.n
        open_ch = s[i]
        close_ch = {"(": ")", "[": "]", "{": "}"}.get(open_ch)
        if not close_ch:
            return i + 1
        depth = 0
        i += 1
        while i < n:
            c = s[i]
            if c in "'\"`":
                i = self.skip_string(i)
                continue
            if c == "/" and i + 1 < n and s[i + 1] in "/*":
                i = self.skip_ws_comments(i)
                continue
            if c == "/" and self._maybe_regex(i):
                i = self._skip_regex(i)
                continue
            if c == open_ch:
                depth += 1
                i += 1
                continue
            if c == close_ch:
                if depth == 0:
                    return i + 1
                depth -= 1
                i += 1
                continue
            i += 1
        return i

    def _maybe_regex(self, i: int) -> bool:
        j = i - 1
        while j >= 0 and self.s[j] in " \t":
            j -= 1
        if j < 0:
            return True
        return self.s[j] in "=([,!&|?:;{>~+-" or self.s[max(0, j - 5):j + 1].endswith("return")

    def _skip_regex(self, i: int) -> int:
        s, n = self.s, self.n
        i += 1
        in_class = False
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "[" and not in_class:
                in_class = True
                i += 1
                continue
            if c == "]" and in_class:
                in_class = False
                i += 1
                continue
            if c == "/" and not in_class:
                i += 1
                while i < n and s[i].isalpha():
                    i += 1
                return i
            if c in "\n\r":
                return i
            i += 1
        return i

    def body_after_params(self, i: int) -> Optional[Tuple[int, int]]:
        i = self.skip_ws_comments(i)
        if i >= self.n or self.s[i] != "(":
            return None
        i = self.match_pair(i)
        i = self.skip_ws_comments(i)
        if i < self.n - 1 and self.s[i:i + 2] == "=>":
            i = self.skip_ws_comments(i + 2)
        if i < self.n and self.s[i] == "{":
            end = self.match_pair(i)
            return i + 1, end - 1
        return None


def parse_regex_literal(src: JsSrc, i: int) -> Tuple[str, int]:
    if i >= src.n or src.s[i] != "/":
        return "", i
    start = i + 1
    i = src._skip_regex(i)
    slash = src.s.rfind("/", start, i)
    if slash < 0:
        return "", i
    return src.s[start:slash], i


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
        r"import\s+(?:type\s+)?(?:(\*\s+as\s+(\w+))|(\{[^}]+\})|([A-Za-z_][\w]*))\s+from\s+['\"]([^'\"]+)['\"]",
        text,
    ):
        spec = m.group(5)
        names: List[str] = []
        if m.group(2):
            names.append(m.group(2))
        elif m.group(3):
            for part in m.group(3).strip("{}").split(","):
                part = part.strip()
                if not part:
                    continue
                if " as " in part:
                    names.append(part.split(" as ")[-1].strip())
                else:
                    names.append(part.strip())
        elif m.group(4):
            names.append(m.group(4))
        _bind_import(mod, names, spec)

    for m in re.finditer(r"import\s+['\"]([^'\"]+)['\"]", text):
        spec = m.group(1)
        if not spec.startswith((".", "/", "~")):
            mod.external_imports.add(normalize_pkg(spec))

    for m in re.finditer(
        r"(?:const|let|var)\s+(\{[^}]+\}|[A-Za-z_][\w]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)",
        text,
    ):
        spec = m.group(2)
        target = m.group(1)
        names = []
        if target.startswith("{"):
            for part in target.strip("{}").split(","):
                part = part.strip()
                if part:
                    names.append(part.split(":")[0].strip())
        else:
            names.append(target)
        _bind_import(mod, names, spec)


def _bind_import(mod: JsModule, names: List[str], spec: str) -> None:
    if spec.startswith((".", "/", "~")):
        for name in names:
            mod.imports[name] = spec
    else:
        pkg = normalize_pkg(spec)
        if pkg.startswith("node:"):
            pkg = pkg.split(":", 1)[1]
        if pkg not in BUILTIN_MODULES:
            mod.external_imports.add(pkg)
        for name in names:
            mod.imports[name] = spec


def _extract_constants_urls_env(mod: JsModule, text: str) -> None:
    for m in re.finditer(
        r"(?:export\s+)?(?:const|let|var)\s+([A-Z][A-Z0-9_]*)\s*=\s*['\"]([^'\"]+)['\"]",
        text,
    ):
        mod.constants[m.group(1)] = m.group(2)

    for m in re.finditer(r"['\"](https?://[^'\"]+)['\"]", text):
        url = m.group(1)
        if any(x in url for x in ("localhost", "127.0.0.1", "example.com", "example.org")):
            continue
        mod.urls.append(url)

    for m in re.finditer(
        r"(?:process\.env|Bun\.env|import\.meta\.env)(?:\.([A-Za-z0-9_]+)|\[['\"]([A-Za-z0-9_]+)['\"]\])",
        text,
    ):
        name = m.group(1) or m.group(2)
        if name and name not in ("NODE_ENV", "npm_package_version"):
            mod.env_vars.add(name)


def _extract_classes(mod: JsModule, src: JsSrc) -> None:
    for m in re.finditer(r"(?:export\s+)?class\s+([A-Za-z_][\w]*)", src.s):
        i = src.skip_ws_comments(m.end())
        if i < src.n and src.s.startswith("extends", i):
            i = src.skip_ws_comments(i + 7)
            while i < src.n and (src.s[i].isalnum() or src.s[i] in "._$"):
                i += 1
            i = src.skip_ws_comments(i)
        if i >= src.n or src.s[i] != "{":
            continue
        end = src.match_pair(i)
        body = src.s[i + 1:end - 1]
        sym = Symbol(name=m.group(1), kind="class", file=mod.file, body=body)
        _extract_methods(sym, body)
        sym.constructed = _constructed_types(body)
        sym.return_news = re.findall(r"\breturn\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(", body)
        mod.classes[sym.name] = sym


def _extract_methods(sym: Symbol, body: str) -> None:
    inner = JsSrc(body)
    for m in re.finditer(r"(?:async\s+)?(?:static\s+)?(\#?[A-Za-z_][\w]*)\s*\(", body):
        name = m.group(1)
        if name in SKIP_CALL_NAMES:
            continue
        span = inner.body_after_params(m.end() - 1)
        if not span:
            continue
        method_body = body[span[0]:span[1]]
        if name == "constructor":
            sym.bindings.update(_const_bindings(method_body))
            for bm in re.finditer(r"this\.([A-Za-z_][\w]*)\s*=\s*([A-Za-z_][\w]*)", method_body):
                if bm.group(1) == bm.group(2):
                    sym.bindings[bm.group(1)] = bm.group(2)
        sym.methods[name] = method_body


def _extract_functions(mod: JsModule, src: JsSrc) -> None:
    for m in re.finditer(
        r"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+(\#?[A-Za-z_][\w]*)\s*\(",
        src.s,
    ):
        span = src.body_after_params(m.end() - 1)
        if not span:
            continue
        body = src.s[span[0]:span[1]]
        _add_function(mod, m.group(1), body)

    for m in re.finditer(
        r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_][\w]*)\s*=>",
        src.s,
    ):
        i = src.skip_ws_comments(m.end())
        if i < src.n and src.s[i] == "{":
            end = src.match_pair(i)
            _add_function(mod, m.group(1), src.s[i + 1:end - 1])


def _add_function(mod: JsModule, name: str, body: str) -> None:
    sym = Symbol(name=name, kind="function", file=mod.file, body=body)
    sym.bindings = _const_bindings(body)
    sym.constructed = _constructed_types(body)
    sym.return_news = re.findall(r"\breturn\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(", body)
    for cm in re.finditer(r"(?:async\s+)?function\s+(\#?[A-Za-z_][\w]*)\s*\(", body):
        inner = JsSrc(body)
        span = inner.body_after_params(cm.end() - 1)
        if span:
            sym.methods[cm.group(1)] = body[span[0]:span[1]]
    mod.functions[name] = sym


def _const_bindings(body: str) -> Dict[str, str]:
    bindings: Dict[str, str] = {}
    for m in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*[^;]{0,400}?\bnew\s+([A-Z][A-Za-z0-9_]*)\s*\(",
        body,
        re.S,
    ):
        bindings[m.group(1)] = m.group(2)
    for m in re.finditer(
        r"(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*[^;]{0,400}?\b(create[A-Z][A-Za-z0-9_]*)\s*\(",
        body,
        re.S,
    ):
        bindings.setdefault(m.group(1), m.group(2))
    return bindings


def _constructed_types(body: str) -> List[str]:
    return re.findall(r"\bnew\s+([A-Z][A-Za-z0-9_]*)\s*\(", body)


def _without_comments(src_text: str) -> str:
    src_text = re.sub(r"/\*.*?\*/", "", src_text, flags=re.S)
    src_text = re.sub(r"^\s*//.*$", "", src_text, flags=re.M)
    src_text = re.sub(r"\s//.*$", "", src_text, flags=re.M)
    return src_text


def _extract_spawns(mod: JsModule, text: str) -> None:
    code = _without_comments(text)
    for m in re.finditer(r"\bspawn(?:Process)?\s*\(\s*['\"]([^'\"]+)['\"]", code):
        cmd = m.group(1).strip()
        if cmd and cmd not in {"help", "-h", "--help"}:
            mod.spawns.append(cmd)
    if re.search(r"(?:this\.)?spawn(?:Process)?\s*\(\s*(?:this\.)?command\b", code):
        defaults = re.findall(r"command\s*=\s*['\"]([^'\"]+)['\"]", code)
        defaults += re.findall(r"command:\s*options\.\w+\s*\?\?\s*['\"]([^'\"]+)['\"]", code)
        defaults += re.findall(r"command\s*=\s*options\.\w+\s*\?\?\s*['\"]([^'\"]+)['\"]", code)
        for cmd in defaults:
            if cmd not in {"help", "-h", "--help"}:
                mod.spawns.append(cmd)


def _extract_routes(mod: JsModule, src: JsSrc) -> None:
    text = src.s
    for m in re.finditer(
        r"if\s*\(\s*method\s*===?\s*['\"](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]\s*&&\s*"
        r"(?:url\.pathname|pathname)\s*===?\s*['\"]([^'\"]+)['\"]\s*\)",
        text,
    ):
        body = _block_after(src, m.end())
        mod.routes.append(Route(m.group(1).upper(), m.group(2), mod.file, body, _nearest_scope(mod, m.start()), "server"))

    for m in re.finditer(
        r"if\s*\(\s*(?:url\.pathname|pathname)\s*===?\s*['\"]([^'\"]+)['\"]\s*&&\s*"
        r"method\s*===?\s*['\"](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]\s*\)",
        text,
    ):
        body = _block_after(src, m.end())
        mod.routes.append(Route(m.group(2).upper(), m.group(1), mod.file, body, _nearest_scope(mod, m.start()), "server"))

    for m in re.finditer(
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?:url\.pathname|pathname)\.match\(\s*/",
        text,
    ):
        rx, after = parse_regex_literal(src, m.end() - 1)
        if not rx:
            continue
        path = js_regex_to_path(rx)
        window = text[after:after + 400]
        mm = re.search(r"method\s*===?\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]", window)
        method = mm.group(1).upper() if mm else "GET"
        if_match = re.search(rf"if\s*\([^)]*{re.escape(m.group(1))}[^)]*\)", text[after:after + 800])
        body = ""
        if if_match:
            body = _block_after(src, after + if_match.end())
        mod.routes.append(Route(method, path, mod.file, body, _nearest_scope(mod, m.start()), "server"))

    for m in re.finditer(
        r"(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*['\"]([^'\"]+)['\"]",
        text,
        re.I,
    ):
        body = _block_after(src, m.end())
        mod.routes.append(Route(m.group(1).upper(), m.group(2), mod.file, body, _nearest_scope(mod, m.start()), "server"))

    for m in re.finditer(r"/(\^\\?/attachments\\?/[^/\n]+\\?/[^/\n]+\$?)/", text):
        path = js_regex_to_path(m.group(1))
        if "image" in path or "attachment" in path:
            if not any(r.path == path for r in mod.routes):
                mod.routes.append(Route("GET", path, mod.file, "", _nearest_scope(mod, m.start()), "server"))


def _block_after(src: JsSrc, i: int) -> str:
    i = src.skip_ws_comments(i)
    if i < src.n and src.s[i] == "{":
        end = src.match_pair(i)
        return src.s[i + 1:end - 1]
    return ""


def _nearest_scope(mod: JsModule, pos: int) -> str:
    best = ""
    best_pos = -1
    for name, _sym in list(mod.functions.items()) + list(mod.classes.items()):
        idx = mod.text.find(f"function {name}")
        if idx < 0:
            idx = mod.text.find(f"const {name}")
        if idx < 0:
            idx = mod.text.find(f"class {name}")
        if 0 <= idx <= pos and idx > best_pos:
            best_pos = idx
            best = name
    return best


def _extract_client_api(mod: JsModule, src: JsSrc) -> None:
    for fn in mod.functions.values():
        for m in re.finditer(
            r"([A-Za-z_][\w]*)\s*:\s*(?:async\s*)?(?:function\s*)?(?:\([^)]*\)|[A-Za-z_][\w]*)?\s*=>\s*"
            r"(?:[A-Za-z_][\w]*\s*)?request\(\s*([`'\"])([^`'\"]+)\2",
            fn.body,
        ):
            method = "GET"
            window = fn.body[m.end():m.end() + 180]
            mm = re.search(r"method\s*:\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]", window)
            if mm:
                method = mm.group(1).upper()
            elif m.group(1).lower().startswith(("send", "create", "update", "register", "interrupt", "post")):
                method = "POST"
            path = normalize_route_path(m.group(3))
            mod.client_calls.append((m.group(1), method, path))


def _detect_entrypoint(mod: JsModule, text: str) -> None:
    if re.search(r"\bregisterRootComponent\s*\(", text):
        mod.entrypoint = "ui"
    elif re.search(r"\bhttp\.createServer\s*\(|\bcreateServer\s*\(|\bapp\.listen\s*\(", text):
        mod.entrypoint = "http"
    elif re.search(r"\blisten\s*\(\s*(?:port|host)\b", text) and "createBridgeServer" in text:
        mod.entrypoint = "http"
    elif Path(mod.file).name in {"index.js", "main.js", "server.js", "App.js", "app.js"} and "createServer" in text:
        mod.entrypoint = "http"


def _detect_io(mod: JsModule, text: str) -> None:
    if re.search(r"\bfetch\s*\(|\brequest\s*\(|createServer\s*\(|\bapp\.(get|post)\s*\(", text):
        mod.io_kind.add("http")
    if re.search(r"\bspawn\s*\(|spawnProcess", text):
        mod.io_kind.add("process")
    if re.search(r"\b(readFile|writeFile|readdir|createReadStream|homedir)\s*\(", text):
        mod.io_kind.add("disk")
    if any(pkg in mod.external_imports for pkg in DEVICE_IO_PACKAGES):
        mod.io_kind.add("device")
    if mod.urls:
        mod.io_kind.add("http-external")


def extract_calls(body: str) -> List[Call]:
    calls: List[Call] = []
    for m in re.finditer(
        r"(?:await\s+)?((?:this\.)?\#?[A-Za-z_][\w]*)(?:\.(\#?[A-Za-z_][\w]*))*\s*\(",
        body,
    ):
        parts = re.findall(r"\#?[A-Za-z_][\w]*", m.group(0).split("(")[0].replace("await", ""))
        parts = [p for p in parts if p != "await"]
        if not parts:
            continue
        if parts[0] in SKIP_CALL_NAMES:
            continue
        if len(parts) == 1:
            calls.append(Call(None, parts[0], parts, m.group(0)))
        else:
            calls.append(Call(parts[0], parts[-1], parts, m.group(0)))
    return calls


def body_fields(body: str) -> List[str]:
    fields = []
    seen = set()
    for m in re.finditer(r"(?<![\w.])body\.([A-Za-z_][\w]*)", body):
        if m.group(1) not in seen and m.group(1) not in {"ok", "error", "status", "get", "items", "keys", "values"}:
            seen.add(m.group(1))
            fields.append(m.group(1))
    return fields


SKIP_TRACE = {
    "sendJson", "readJson", "httpError", "projectMessageResult", "normalizePromptInput",
    "normalizeImageAttachments", "stringValue", "timestampFrom", "requestOrigin",
    "remove", "prune", "listSessions", "listDevices", "readInternetProbe",
    "internetFailureDetails", "publicPhoneView", "normalizeNonNegativeMs",
    "projectPrivateToolImageAttachments", "timeMsFrom", "shortSessionId",
    "createSessionTitle", "createId", "nowIso", "normalizeImageAttachment",
    "buildHealthPayload",
}

RECURSE_METHODS = {
    "sendMessage", "startMessage", "prompt", "request", "start", "interrupt",
    "sendNotification", "sendExpoPushRequest", "put", "#runPrompt",
    "run", "retrieve", "upsert", "get_secret", "track", "invoke",
    "create_agent", "create_thread", "create_message", "create_and_process_run",
}

SERVICE_CREATE_RE = re.compile(
    r"^create(?:[A-Z].*(?:Server|Store|Api|API|Cache|State|Reader|Registry|Index|Client|Transport)"
    r"|_.*(?:server|store|api|cache|state|reader|registry|index|client|transport|agent|app|telemetry))$"
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class ArchitectureScanner:
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.root}")
        self.repo_name = self.root.name
        self.modules: Dict[str, JsModule] = {}
        self.manifest_deps: Dict[str, Set[str]] = defaultdict(set)
        self.all_manifest_deps: Set[str] = set()
        self.config_files: List[str] = []
        self.declared_env_vars: Dict[str, Dict[str, str]] = defaultdict(dict)
        self.consumed_env_vars: Dict[str, Set[str]] = defaultdict(set)
        self.resolved_index: Dict[str, Tuple[str, str]] = {}
        self.trace_route_spec: Optional[str] = None
        self.py_modules: Dict[str, dict] = {}
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
        # Python: from .blob import x  -> spec ".blob"
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
        for pym in self.py_modules.values():
            if is_test_path(pym["file"]):
                continue
            for route in pym["routes"]:
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
        for rel, pym in self.py_modules.items():
            if is_test_path(rel) or is_ops_path(rel):
                continue
            if not (pym["entrypoint"] or pym["routes"]):
                continue
            top = rel.split("/")[0] if "/" in rel else "root"
            g = groups.setdefault(top, {
                "id": top,
                "kind": "http",
                "entrypoints": [],
                "files": set(),
            })
            g["kind"] = "http"
            g["entrypoints"].append(rel)
            g["files"].add(rel)
        for g in groups.values():
            for ep in list(g["entrypoints"]):
                if ep in self.modules:
                    g["files"] |= self._local_import_tree(ep, 8)
            top = g["id"]
            for rel in list(self.py_modules):
                if is_test_path(rel) or is_ops_path(rel):
                    continue
                if (rel.split("/")[0] if "/" in rel else "root") == top:
                    g["files"].add(rel)
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
        comps = []
        seen_names = set()
        for rel in sorted(runtime["files"]):
            mod = self.modules.get(rel)
            if not mod or is_test_path(rel):
                continue
            if mod.entrypoint == "ui" and Path(rel).name == "index.js":
                continue
            if mod.entrypoint == "http" and not mod.routes and "createBridgeServer" not in mod.functions:
                if not any(name.startswith("create") and "Server" in name for name in mod.functions):
                    continue
            for sym in list(mod.classes.values()) + list(mod.functions.values()):
                if not self._keep_symbol(sym, mod, runtime):
                    continue
                if sym.name in seen_names:
                    continue
                seen_names.add(sym.name)
                comps.append({
                    "id": mermaid_id("C", sym.name),
                    "name": sym.name,
                    "file": rel,
                    "kind": sym.kind,
                    "runtime": runtime["id"],
                })
        ranked = []
        for c in comps:
            score = 0
            if c["name"].endswith(("Server", "Store", "Transport", "Registry", "Index", "Api", "API", "Agent")):
                score += 30
            if c["name"].endswith(("_store", "_index", "_reader", "_agent", "_app", "_telemetry")):
                score += 25
            if c["name"].startswith("create") and SERVICE_CREATE_RE.match(c["name"]):
                score += 20
            if c["kind"] == "class":
                score += 10
            if c["name"].startswith("Fake"):
                score -= 50
            ranked.append((score, c["name"], c))
        ranked.sort(key=lambda x: (-x[0], x[1]))
        return [c for _, _, c in ranked[:14]]

    def _component_title(self, mod: JsModule, fallback: str) -> str:
        if mod.entrypoint == "ui":
            return "App"
        if "createServer" in mod.text or "createBridgeServer" in mod.text:
            if "createBridgeServer" in mod.functions:
                return "createBridgeServer"
            return "HTTP server"
        return fallback

    def _keep_symbol(self, sym: Symbol, mod: JsModule, runtime: dict) -> bool:
        name = sym.name
        if UTIL_NAME_RE.match(name) or name.endswith("Error"):
            return False
        if name.startswith("Fake"):
            return False
        if is_ops_path(mod.file) or "/ui/" in mod.file.replace("\\", "/"):
            return False
        if Path(mod.file).name in {"theme.js", "log.js", "ids.js", "dev-warn.js", "message-rendering.js"}:
            return False
        if name.startswith("default") and name.endswith(("Index", "Probe", "Factory")):
            return False
        if "ViewState" in name or name.endswith("View"):
            return False
        if name in {"startBridge", "start"}:
            return False
        if sym.kind == "class":
            return True
        if SERVICE_CREATE_RE.match(name):
            return True
        if name in {"App"} and runtime.get("kind") == "ui":
            return True
        if name.startswith("create") and ("createServer" in sym.body or "request(" in sym.body):
            return True
        if any(u["function"] == name and u["file"] == mod.file for u in self.import_uses):
            return True
        return False

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
                if "exp.host" in url and "push" in url:
                    add("Expo Push API", "http", url, 10, {rel})
                elif "generate_204" in url or "gstatic" in url:
                    add("Internet probe", "http", url, 9, {rel})
                else:
                    add(host, "http", url, 5, {rel})
            for cmd in mod.spawns:
                add(f"{cmd} process", "process", f"spawn({cmd})", 10, {rel})
            if "disk" in mod.io_kind and ("sessions" in mod.text or "homedir" in mod.text):
                add("Local session files", "disk", rel, 8, {rel})
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

        stores = [c for c in components if c["name"].endswith("Store") and not c["name"].startswith("create")]
        for c in components:
            mod = self.modules.get(c["file"])
            if not mod:
                continue
            sym = mod.classes.get(c["name"]) or mod.functions.get(c["name"])
            if not sym:
                continue
            if c["name"].endswith("Server") or SERVICE_CREATE_RE.match(c["name"] or ""):
                for bound_type in dict.fromkeys(list(sym.bindings.values()) + sym.constructed):
                    if bound_type.startswith("Fake") or bound_type.endswith("Error"):
                        continue
                    target = by_name.get(bound_type)
                    if target:
                        link(c["id"], target["id"], "owns")
        for fn_mod in self.modules.values():
            if is_test_path(fn_mod.file) or is_ops_path(fn_mod.file):
                continue
            for fn in fn_mod.functions.values():
                if "Factory" not in fn.name and "transport" not in fn.name.lower():
                    continue
                news = [n for n in (fn.return_news or _constructed_types(fn.body)) if not n.startswith("Fake")]
                if not news:
                    continue
                target = by_name.get(news[-1])
                for store in stores:
                    if target:
                        link(store["id"], target["id"], "transport")
        api = next((c for c in components if c["name"].endswith("Api") or c["name"].endswith("API")), None)
        app = by_name.get("App")
        server = next((c for c in components if "Server" in c["name"]), None)
        if app and api:
            link(app["id"], api["id"], "uses")
        if api and server:
            link(api["id"], server["id"], "HTTP + Bearer")
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

        add("User", "HTTP", f"{route.method} {route.path}", "authenticated HTTP", route.file)
        if "isAuthorized" in (self.modules.get(route.file).text if route.file in self.modules else ""):
            add("HTTP", "isAuthorized", "Bearer / loopback check", "401 or continue", route.file)

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
                if call.method in SKIP_TRACE or call.method in SKIP_CALL_NAMES:
                    continue
                if call.recv in {None, "self", "this"} and call.method == name:
                    continue
                target_name = call.method
                recv_type = None
                if call.recv in {None, "this"} and walking and target_name in walking.methods:
                    if target_name not in RECURSE_METHODS:
                        continue
                    recv_type = walking.name
                elif call.recv and call.recv not in {"this", "options", "console"}:
                    recv_type = local_bindings.get(call.recv)
                    if call.recv == "session" and "transport" in call.chain:
                        recv_type = self._infer_transport(file) or recv_type
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
                        if cls and cls.kind == "class" and (target_name in cls.methods or target_name in RECURSE_METHODS):
                            resolved = cls
                            break
                if not resolved:
                    continue
                if resolved.name.endswith("Error") or resolved.name.startswith("Fake"):
                    continue
                actor = resolved.name
                if actor in SKIP_TRACE:
                    continue
                if actor == src and call.recv in {None, "self", "this"}:
                    continue
                interesting = (
                    resolved.kind == "class"
                    or target_name in RECURSE_METHODS
                    or SERVICE_CREATE_RE.match(resolved.name or "")
                    or bool(self.uses_for(resolved.file, resolved.name))
                    or target_name in {"storeMessageAttachments", "getResumeSession", "sendMessage", "startMessage"}
                )
                if not interesting:
                    continue
                add(src, actor, target_name, call.raw.strip()[:70], resolved.file)
                next_body = resolved.methods.get(target_name) or resolved.methods.get("#runPrompt") or resolved.body
                if next_body and (target_name in RECURSE_METHODS or resolved.kind == "class" or SERVICE_CREATE_RE.match(resolved.name or "") or self.uses_for(resolved.file, resolved.name)):
                    walk(actor, resolved.file, resolved.name if resolved.kind == "class" else resolved.name, next_body, depth + 1)
                    if target_name in {"start", "prompt"} and ("spawn" in (next_body or resolved.body or "") or "spawnProcess" in (next_body or "")):
                        cmds = self.modules.get(resolved.file).spawns if resolved.file in self.modules else []
                        cmd = cmds[0] if cmds else "child process"
                        add(actor, f"{cmd} process", "spawn", f"stdio JSONL ({cmd})", resolved.file)

        walk("HTTP", route.file, scope_name or Path(route.file).stem, route.body, 0)

        route_mod = self.modules.get(route.file)
        if route_mod and "session_completed" in route_mod.text:
            add("SessionStore", "PushNotificationRegistry", "sendNotification", "on session_completed if chat view is stale", "bridge/src/push-notifications.js")
            add("PushNotificationRegistry", "Expo Push API", "POST /api/v2/push/send", "https://exp.host/--/api/v2/push/send", "bridge/src/push-notifications.js")

        return steps

    def _infer_transport(self, file: str) -> Optional[str]:
        mod = self.modules.get(file)
        if not mod:
            return None
        for fn in mod.functions.values():
            if "Transport" in fn.name or "Factory" in fn.name:
                if "OmpRpcTransport" in fn.return_news or "OmpRpcTransport" in fn.constructed:
                    return "OmpRpcTransport"
                if fn.return_news:
                    return fn.return_news[-1]
        for other in self.modules.values():
            if is_test_path(other.file):
                continue
            for fn in other.functions.values():
                if "Factory" in fn.name or "transport" in fn.name.lower():
                    if fn.return_news:
                        real = [n for n in fn.return_news if "Fake" not in n]
                        return (real or fn.return_news)[-1]
        return "OmpRpcTransport" if any("OmpRpcTransport" in m.classes for m in self.modules.values()) else None

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
        for rid, rt in runtimes.items():
            if files & set(rt["files"]):
                comps = components_by_rt.get(rid, [])
                return next((c for c in comps if "Server" in c["name"] or c["kind"] == "entrypoint"), comps[0] if comps else None)
        return None

    def render_markdown(self) -> str:
        runtimes = self.runtimes()
        components_by_rt = {rid: self.architectural_components(rt) for rid, rt in runtimes.items()}
        all_components = [c for cs in components_by_rt.values() for c in cs]
        externals = self.externals(include_device=False)
        device_ext = self.externals(include_device=True)
        edges = self.composition_edges(all_components)
        routes = self.all_routes()
        flow_route = self.choose_flow_route()

        md: List[str] = []
        md.append(f"# {self.repo_name} — Architecture\n")
        md.append(
            "Generated by `arch-map` using **deterministic structural JS/TS analysis** "
            "and **Python AST** (functions, classes, imports, routes, and call resolution) "
            "plus **function → import** edges (the import name as written in source, not a renamed cloud product). "
            "No language server is used in this pass. Same tree → same document.\n"
        )
        md.append("| View | Question | Source |")
        md.append("| :--- | :--- | :--- |")
        md.append("| **Level 1 — System context** | Who talks to this system, and what is outside it? | Entrypoints, URL literals, `spawn`, imported packages |")
        md.append("| **Level 2 — Service topology** | Which functions use which imports? | Function body mentions of imported names |")
        md.append("| **Level 3 — Data flow** | What happens on one request? | Handler call graph, then each function's imports |")
        md.append("")
        md.append("---\n")

        md.extend(self._render_level1(runtimes, components_by_rt, externals))
        md.extend(self._render_level2(runtimes, components_by_rt, device_ext, edges, routes))
        md.extend(self._render_level3(flow_route, runtimes))
        md.extend(self._render_routes(routes))
        md.extend(self._render_env())
        return "\n".join(md)

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
            "## Level 1 — System context\n",
            "People and external systems around this repository. Internal folders such as `test/` and `scripts/` are omitted. "
            "External nodes are import names (`azure.cosmos`, `azure.ai.projects`, `gremlin_python...`) plus spawn/URL I/O. No product-name translation.\n",
            "```mermaid",
            "flowchart TB",
            '    User["User"]',
            f'    subgraph System["{mermaid_label(self.repo_name)}"]',
        ]
        rt_ids = {}
        for rid, rt in sorted(runtimes.items()):
            nid = mermaid_id("RT", rid)
            rt_ids[rid] = nid
            title = self._runtime_title(rt)
            files = ", ".join(Path(f).name for f in rt["entrypoints"][:2])
            md.append(f'        {nid}["{mermaid_label(title)}\\n{files}"]')
        md.append("    end")
        for ext in externals:
            if ext["kind"] == "disk":
                md.append(f'    {ext["id"]}(["{mermaid_label(ext["name"])}"])')
            else:
                md.append(f'    {ext["id"]}["{mermaid_label(ext["name"])}"]')

        ui = next((rid for rid, rt in runtimes.items() if rt["kind"] == "ui"), None)
        http = next((rid for rid, rt in runtimes.items() if rt["kind"] == "http"), None)
        if ui:
            md.append(f"    User -->|touch / type| {rt_ids[ui]}")
        elif http:
            md.append(f"    User --> {rt_ids[http]}")
        if ui and http:
            md.append(f"    {rt_ids[ui]} -->|HTTP + Bearer| {rt_ids[http]}")

        http_id = rt_ids.get(http) if http else (rt_ids[next(iter(rt_ids))] if rt_ids else None)
        ui_id = rt_ids.get(ui) if ui else None
        kind_label = {
            "http": "HTTPS", "process": "spawn", "disk": "read/write",
            "import": "import", "device": "import",
        }
        for ext in externals:
            if http_id:
                md.append(f"    {http_id} -->|{kind_label.get(ext['kind'], ext['kind'])}| {ext['id']}")
            elif ui_id:
                md.append(f"    {ui_id} -->|{kind_label.get(ext['kind'], ext['kind'])}| {ext['id']}")
        md.append("```\n")
        if externals:
            md.append("| External system | Kind | Evidence |")
            md.append("| :--- | :--- | :--- |")
            for ext in externals:
                md.append(f"| **{ext['name']}** | `{ext['kind']}` | `{ext['evidence']}` |")
            md.append("")
        md.append("---\n")
        return md

    def _render_level2(self, runtimes, components_by_rt, externals, edges, routes) -> List[str]:
        md = [
            "## Level 2 — Service topology\n",
            "Deployable / process pieces and the components they compose. UI widgets and test doubles are omitted. "
            "Each function points at the import names it mentions. `gremlin` stays `gremlin`.\n",
            "```mermaid",
            "flowchart LR",
        ]
        for rid, rt in sorted(runtimes.items()):
            title = self._runtime_title(rt)
            md.append(f'    subgraph {mermaid_id("SG", rid)}["{mermaid_label(title)}"]')
            for c in components_by_rt.get(rid, []):
                md.append(f'        {c["id"]}["{mermaid_label(c["name"])}"]')
            md.append("    end")

        shown_ext = []
        for ext in externals:
            shown_ext.append(ext)
            md.append(f'    {ext["id"]}["{mermaid_label(ext["name"])}"]')

        for src, dst, label in edges:
            md.append(f"    {src} -->|{mermaid_label(label)}| {dst}")

        by_name = {c["name"]: c for cs in components_by_rt.values() for c in cs}
        pkg_ids = {ext["name"]: ext["id"] for ext in shown_ext}
        for u in self.import_uses:
            src = by_name.get(u["function"])
            dst = pkg_ids.get(u["package"])
            if src and dst:
                md.append(f"    {src['id']} -->|{mermaid_label(u['binding'])}| {dst}")

        kind_label = {"http": "HTTPS", "process": "stdio", "disk": "fs"}
        for ext in shown_ext:
            if ext["kind"] == "import":
                continue
            owner = self._owner_component(set(ext.get("files") or ()), components_by_rt, runtimes)
            if owner:
                md.append(f"    {owner['id']} -.->|{kind_label.get(ext['kind'], ext['kind'])}| {ext['id']}")

        md.append("```\n")
        if self.import_uses:
            md.append("Function → import (the graph above is this table):\n")
            md.append("| Function | Import | Binding | File |")
            md.append("| :--- | :--- | :--- | :--- |")
            for u in sorted(self.import_uses, key=lambda x: (x["function"], x["package"])):
                md.append(f"| `{u['function']}` | `{u['package']}` | `{u['binding']}` | `{u['file']}` |")
            md.append("")
        md.append("See **Routes** below for the full endpoint list.\n")
        md.append("---\n")
        return md

    def _render_level3(self, route: Optional[Route], runtimes) -> List[str]:
        md = ["## Level 3 — Request data flow\n"]
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
            + ". Handler call-graph walk (no language server).\n"
        )
        if fields:
            md.append("Request body fields read in the handler: " + ", ".join(f"`{f}`" for f in fields) + ".\n")
        if "async" in fields:
            md.append("Branch: `body.async` chooses `startMessage` (non-blocking) vs `sendMessage` (await completion).\n")

        def pid(name: str) -> str:
            aliases = {
                "User": "User",
                "App": "App",
                "HTTP": "HTTP",
                "Api": "Api",
                "isAuthorized": "Auth",
                "SessionStore": "Store",
                "OmpRpcTransport": "Rpc",
                "PushNotificationRegistry": "Push",
                "Expo Push API": "Expo",
                "createImageAttachmentStore": "Images",
                "storeMessageAttachments": "Attach",
                "getResumeSession": "Resume",

            }
            return aliases.get(name, mermaid_id("P", name))

        md.append("```mermaid")
        md.append("sequenceDiagram")
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
        md.append("| Step | From → to | Action | Where |")
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
            if n > 16:
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
        md.append("| Environment variable | Consumed in | Declared in | Type |")
        md.append("| :--- | :--- | :--- | :--- |")
        for ev in all_env:
            consumers = ", ".join(f"`{Path(p).name}`" for p in sorted(self.consumed_env_vars.get(ev, []))[:3]) or "*Declared only*"
            decls = [f"`{cf}`" for cf, vdict in self.declared_env_vars.items() if ev in vdict]
            decl = ", ".join(decls) or "*Runtime only*"
            md.append(f"| `{ev}` | {consumers} | {decl} | {classify_env(ev)} |")
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
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {target_path} ...", file=sys.stderr)
    scanner = ArchitectureScanner(str(target_path))
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
