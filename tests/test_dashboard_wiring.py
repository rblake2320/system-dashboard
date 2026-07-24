"""Static contracts that keep the single-file dashboard UI wired to Flask."""
from __future__ import annotations

import ast
import re
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "dashboard.py"
TEXT = SOURCE.read_text(encoding="utf-8")


def _routes() -> set[str]:
    tree = ast.parse(TEXT)
    result: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
            ):
                result.add(str(decorator.args[0].value))
    return result


def _normalize_client_path(path: str) -> str:
    path = path.split("?", 1)[0]
    for route in _routes():
        prefix = route.split("<", 1)[0]
        if "<" in route and path.startswith(prefix):
            return route
    return path


def test_literal_fetch_paths_have_flask_routes():
    script = TEXT[TEXT.find("<script>") : TEXT.rfind("</script>")]
    fetches = set(re.findall(r"""fetch\(\s*['"]([^'"]+)""", script))
    missing = sorted(
        path for path in fetches if _normalize_client_path(path) not in _routes()
    )
    assert not missing, f"client fetch paths without Flask routes: {missing}"


def test_inline_click_handlers_have_javascript_functions():
    script = TEXT[TEXT.find("<script>") : TEXT.rfind("</script>")]
    functions = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)\s*\(", script))
    handlers = set(
        re.findall(r'onclick="(?:event\.[^;]+;)?\s*([A-Za-z_$][\w$]*)\s*\(', TEXT)
    )
    handlers -= {"if", "fetch"}
    missing = sorted(handlers - functions)
    assert not missing, f"onclick handlers without JavaScript functions: {missing}"


def test_previously_dormant_controls_are_exposed():
    assert "runSystemReview()" in TEXT
    assert "exportSystemState()" in TEXT
    assert "killFleetAgent(" in TEXT
    assert "_setChatModelLabel" not in TEXT
