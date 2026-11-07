"""Conservative AST patching with auditable application routes.

Ambiguous names, escaping paths, stale line snapshots, and extra definitions are
failures. No fuzzy replacement is allowed to silently select another function.
"""
import ast
from collections import Counter
from pathlib import Path
import re
import textwrap

from parsers.ast_utils import boundaries, locate, function_at


class AuditedCodePatcher:
    def __init__(self, repo_path):
        from parsers.code_fetcher import CodeFetcher
        self.repo_path = Path(repo_path).resolve()
        self.code_fetcher = CodeFetcher(str(self.repo_path))
        self.application_counts = Counter()
        self.application_events = []
        self.last_application = None

    def parse_fix_response(self, response):
        scope = re.search(r"^SCOPE:\s*(\w+)", response, re.I | re.M)
        explanation = re.search(r"^EXPLANATION:\s*(.+)", response, re.I | re.M)
        blocks = re.findall(r"```(?:python|py)?\s*\n(.*?)```", response, re.S)
        return {"scope": scope.group(1).lower() if scope else "function",
                "explanation": explanation.group(1) if explanation else "",
                "fixed_code": blocks[0].strip() if len(blocks) == 1 else ""}

    def apply_fix(self, file_path, fix_data, finding_details):
        route = "rejected"
        event = {"file": file_path, "scope": fix_data.get("scope"), "route": route}
        try:
            path = (self.repo_path / file_path).resolve()
            if not path.is_relative_to(self.repo_path) or ".git" in path.relative_to(self.repo_path).parts:
                raise ValueError("Patch target must be a source file inside the clone")
            source = path.read_text(encoding="utf-8")
            lines = source.splitlines(keepends=True)
            tree = ast.parse(source)
            code = textwrap.dedent(fix_data.get("fixed_code", "")).strip()
            if not code:
                raise ValueError("Response must contain exactly one nonempty Python code block")
            scope = fix_data.get("scope", "function")
            if scope == "function":
                replacement = ast.parse(code)
                if len(replacement.body) != 1 or not isinstance(replacement.body[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
                    raise ValueError("Function patch must contain exactly one function")
                new_node = replacement.body[0]
                target = finding_details.get("function_name")
                if target:
                    node = locate(tree, target)
                    route = "ast_name"
                else:
                    match = function_at(tree, finding_details.get("start_line", 0))
                    if not match or match[1].name != new_node.name:
                        raise ValueError("No verified function target; re-build context")
                    target, node = match
                    route = "ast_line_fallback"
                if node.name != new_node.name or type(node) is not type(new_node):
                    raise ValueError("Patch changes the target function name or async kind")
                start, end = boundaries(node)
                # Preserve the original decorators exactly, including multiline arguments.
                if new_node.decorator_list:
                    if [ast.dump(d) for d in node.decorator_list] != [ast.dump(d) for d in new_node.decorator_list]:
                        raise ValueError("Patch changes decorators")
                    code = "\n".join(code.splitlines()[new_node.lineno - 1:])
                prefix = "".join(lines[start - 1:node.lineno - 1])
                indent = re.match(r"\s*", lines[node.lineno - 1]).group(0)
                changed = prefix + textwrap.indent(code, indent) + "\n"
            elif scope == "line":
                if finding_details.get("function_name"):
                    raise ValueError("A bound function requires function scope; line scope cannot replace it")
                start = finding_details.get("start_line", 0)
                end = finding_details.get("end_line") or start
                expected = finding_details.get("expected_original")
                if not (1 <= start <= end <= len(lines)) or expected is None:
                    raise ValueError("Line patch requires a valid current range and expected_original snapshot")
                if "".join(lines[start - 1:end]).rstrip("\r\n") != expected.rstrip("\r\n"):
                    raise ValueError("Line snapshot is stale; re-build context")
                indent = re.match(r"[ \t]*", lines[start - 1]).group(0)
                changed = textwrap.indent(code, indent) + "\n"
                route = "verified_line"
            else:
                raise ValueError("Only function or verified line patches are supported; multi-function edits require separate patches")
            result = "".join(lines[:start - 1]) + changed + "".join(lines[end:])
            # Mandatory application integrity; optional experimental gates are separate.
            ast.parse(result)
            if result == source:
                raise ValueError("Patch makes no source change")
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(result)
            event.update(success=True, route=route, target=target if scope == "function" else None)
            message = f"Applied via {route}"
        except (OSError, SyntaxError, ValueError, TypeError) as exc:
            event.update(success=False, route=route, error=str(exc))
            message = str(exc)
        self.application_counts["attempts"] += 1
        self.application_counts["success" if event["success"] else "failures"] += 1
        self.application_counts[event["route"]] += 1
        self.application_events.append(event)
        self.last_application = event
        return event["success"], message
