#!/usr/bin/env python3
"""
Project quality gate.

Two rules this codebase holds itself to that a unit test cannot easily express:
nothing is imported that is not used, and every comment is in English because a
world standard written in one author's language does not get adopted.

Run it locally exactly as CI does:

    python tools/quality.py

Standard library only, so it runs before anything is installed.
"""

import ast
import io
import os
import re
import sys

ROOTS = ("uip", "uise", "conformance", "tests", "tools")
EXTRA_FILES = ("demo.py", "demo_node.py")

# Accented characters, inverted punctuation, and common Spanish function words.
# Written to catch prose, not to be a language classifier: a false positive is a
# comment that should be reworded anyway.
NON_ENGLISH = re.compile(
    r"[áéíóúñ¿¡]|\b(el|la|los|las|que|para|con|una|del|por|como|pero|"
    r"firma|recibo|nodo|clave)\b",
    re.IGNORECASE,
)


def python_files(base):
    if os.path.isfile(base):
        return [base]
    found = []
    for directory, subdirectories, names in os.walk(base):
        subdirectories[:] = [name for name in subdirectories if name != "__pycache__"]
        found += [os.path.join(directory, name)
                  for name in names if name.endswith(".py")]
    return found


def imported_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.asname or alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names |= {alias.asname or alias.name for alias in node.names}
    return names


def referenced_names(tree):
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.value.id for node in ast.walk(tree)
              if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)}
    return names


def check(path):
    source = io.open(path, encoding="utf-8").read()
    tree = ast.parse(source, filename=path)
    problems = []

    # `__init__` re-exports on purpose, and a `noqa` marks a deliberate keep.
    if "__init__" not in os.path.basename(path):
        used = referenced_names(tree)
        exported = source.split("__all__")[-1]
        for name in sorted(imported_names(tree)):
            if name in used or "noqa" in source or name in exported:
                continue
            problems.append("imports %s without using it" % name)

    for number, line in enumerate(source.split("\n"), start=1):
        stripped = line.strip()
        if stripped.startswith("#") and NON_ENGLISH.search(stripped):
            problems.append("line %d: comment is not in English" % number)

    return problems


def main():
    paths = list(EXTRA_FILES)
    for root in ROOTS:
        if os.path.isdir(root):
            paths += python_files(root)

    failures = 0
    for path in sorted(set(paths)):
        for problem in check(path):
            print("%s: %s" % (path, problem))
            failures += 1

    print("checked %d files, %d problems" % (len(set(paths)), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
