"""Pipe protocol for the network-isolated document worker."""

from __future__ import annotations

import base64
import json
import resource
import sys
from typing import Any

from worker.printing import compose_pdf
from worker.rendering import convert_office, inspect_pdf, render_page


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    request: Any = json.load(sys.stdin)
    result: Any
    operation = request.get("operation")
    if operation == "inspect_pdf":
        result = inspect_pdf(base64.b64decode(request["data"], validate=True))
    elif operation == "render_page":
        result = render_page(
            base64.b64decode(request["data"], validate=True),
            mime=request["mime"],
            page=request["page"],
            recipe=request.get("recipe", {}),
            max_edge=request.get("max_edge", 1200),
        )
        result = {"data": base64.b64encode(result["data"]).decode("ascii"), **result["info"]}
    elif operation == "convert_office":
        result = convert_office(
            base64.b64decode(request["data"], validate=True),
            filename=request["filename"],
            converter=request["converter"],
        )
        result = {"data": base64.b64encode(result).decode("ascii")}
    elif operation == "compose_pdf":
        sources = {
            key: {
                "mime": source["mime"],
                "data": base64.b64decode(source["data"], validate=True),
            }
            for key, source in request["sources"].items()
        }
        pages = [
            {
                **page,
                "mime": sources[page["source"]]["mime"],
                "data": sources[page["source"]]["data"],
            }
            for page in request["pages"]
        ]
        result = compose_pdf(pages=pages, layout=request["layout"])
        result = {"data": base64.b64encode(result).decode("ascii")}
    else:
        raise ValueError("Unsupported worker operation.")
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
