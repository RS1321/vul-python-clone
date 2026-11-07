"""Qualified Python targets shared by context refresh and patch application."""
import ast


def functions(tree, prefix=""):
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            name = f"{prefix}.{node.name}" if prefix else node.name
            if not isinstance(node, ast.ClassDef):
                yield name, node
            yield from functions(node, name)
        else:
            yield from functions(node, prefix)


def locate(tree, name):
    matches = [(q, n) for q, n in functions(tree)
               if q == name or ("." not in name and n.name == name)]
    if len(matches) != 1:
        raise ValueError(f"Function target {name!r} is missing or ambiguous ({len(matches)} matches)")
    return matches[0][1]


def function_at(tree, line):
    matches = [(q, n) for q, n in functions(tree)
               if min([n.lineno] + [d.lineno for d in n.decorator_list]) <= line <= n.end_lineno]
    if not matches:
        return None
    return min(matches, key=lambda item: item[1].end_lineno - item[1].lineno)


def boundaries(node):
    return min([node.lineno] + [d.lineno for d in node.decorator_list]), node.end_lineno
