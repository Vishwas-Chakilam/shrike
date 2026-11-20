"""Python AST checks. Reviewed files are parsed as data and never imported."""

import ast
from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    remediation: str


RULES = {
    rule.id: rule for rule in (
        Rule("SHR001", "high", "Subprocess explicitly invokes a shell",
             "Pass an argument list and omit shell=True. Keep arguments separate."),
        Rule("SHR002", "high", "YAML uses an unsafe loader",
             "Use yaml.safe_load and validate the resulting data."),
        Rule("SHR003", "high", "TLS certificate verification is disabled",
             "Keep certificate verification enabled and configure a trusted CA if needed."),
    )
}

KEYWORD_RULES = {
    "subprocess.run": ("shell", True, "SHR001"),
    "subprocess.Popen": ("shell", True, "SHR001"),
    "subprocess.call": ("shell", True, "SHR001"),
    "subprocess.check_call": ("shell", True, "SHR001"),
    "subprocess.check_output": ("shell", True, "SHR001"),
    "requests.request": ("verify", False, "SHR003"),
    "requests.get": ("verify", False, "SHR003"),
    "requests.post": ("verify", False, "SHR003"),
    "httpx.Client": ("verify", False, "SHR003"),
    "httpx.AsyncClient": ("verify", False, "SHR003"),
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: Rule
    fingerprint: str


def qualified_name(node: ast.AST | None, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, "")
    if isinstance(node, ast.Attribute):
        parent = qualified_name(node.value, imports)
        if parent:
            return f"{parent}.{node.attr}"
    return ""


def inspect(source: bytes, path: str) -> list[Finding]:
    tree = ast.parse(source, filename=path)
    imports = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                imports[alias.asname or root] = alias.name if alias.asname else root
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    findings = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        function = qualified_name(call.func, imports)
        keywords = {item.arg: item.value for item in call.keywords}
        rule = None
        if function in KEYWORD_RULES:
            flag, expected, rule_id = KEYWORD_RULES[function]
            value = keywords.get(flag)
            if isinstance(value, ast.Constant) and value.value is expected:
                rule = RULES[rule_id]
        elif function in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}:
            loader = keywords.get("Loader") or (call.args[1] if len(call.args) > 1 else None)
            if function.startswith("yaml.unsafe_") or qualified_name(loader, imports) in {
                "yaml.Loader", "yaml.UnsafeLoader", "yaml.CLoader", "yaml.CUnsafeLoader",
            }:
                rule = RULES["SHR002"]
        if rule:
            key = f"{path}\0{rule.id}\0{ast.dump(call)}"
            findings.append(Finding(path, call.lineno, rule, sha256(key.encode()).hexdigest()))
    return sorted(findings, key=lambda finding: (finding.line, finding.rule.id))
