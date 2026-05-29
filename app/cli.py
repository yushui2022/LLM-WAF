"""Command-line entry point for llm-waf."""

from __future__ import annotations

import argparse

import uvicorn

from app.config import settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-waf", description="Start the LLM-WAF gateway.")
    parser.add_argument("--host", default=settings.bind_host, help="Bind host for the gateway process.")
    parser.add_argument("--port", type=int, default=settings.bind_port, help="Bind port for the gateway process.")
    parser.add_argument("--log-level", default="info", help="Uvicorn log level.")
    parser.add_argument("--reload", action="store_true", help="Enable Uvicorn auto-reload for local development.")
    parser.add_argument("--workers", type=int, default=1, help="Number of Uvicorn worker processes.")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    workers = 1 if args.reload else args.workers
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=workers,
        log_level=args.log_level,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
