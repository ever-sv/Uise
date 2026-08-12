#!/usr/bin/env python3
"""
Verify the published API contract.

Two things a reader of `/api/v1/openapi.json` is entitled to assume, and which
therefore have to be machine-checked rather than trusted:

  * A real validator accepts the document. Asserting that it "looks right" is not
    the same as knowing a tool will parse it.
  * Every route the router actually serves appears in it. A contract that omits
    an endpoint, or advertises one that does not exist, is worse than no contract
    because people build against it.

Run it locally exactly as CI does:

    python tools/check_contract.py
"""

import sys

from openapi_spec_validator import validate

from uise import api, openapi


def main():
    document = openapi.document(api.router)
    validate(document)

    registered = {(route.method.lower(), route.template) for route in api.router.routes}
    documented = {(method, path)
                  for path, operations in document["paths"].items()
                  for method in operations}

    difference = registered ^ documented
    if difference:
        print("routes and contract disagree:")
        for method, path in sorted(difference):
            where = "router only" if (method, path) in registered else "contract only"
            print("  %-6s %-44s %s" % (method.upper(), path, where))
        return 1

    print("contract valid: %d operations, every route documented" % len(registered))
    return 0


if __name__ == "__main__":
    sys.exit(main())
