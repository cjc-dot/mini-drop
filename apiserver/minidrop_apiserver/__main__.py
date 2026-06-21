from __future__ import annotations

import argparse
import os

import uvicorn


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minidrop_apiserver")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--runtime-dir", default="~/mini-drop-runtime")
    parser.add_argument("--access-log", action="store_true", help="enable uvicorn non-JSON access logs")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.environ["MINIDROP_RUNTIME"] = args.runtime_dir
    uvicorn.run(
        "minidrop_apiserver.app:create_app",
        host=args.host,
        port=args.port,
        factory=True,
        access_log=args.access_log,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
