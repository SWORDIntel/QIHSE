"""python -m qihse.browser — serve the bridge or run a headless dump."""

from __future__ import annotations

import argparse
import os
import sys


def _nodes_from_env() -> list[str]:
    """Seed nodes from the smoke-drill environment convention
    (QIHSE_NODE0_HOST/QIHSE_NODE0_PORT)."""
    host = os.environ.get("QIHSE_NODE0_HOST")
    port = os.environ.get("QIHSE_NODE0_PORT")
    if host and port:
        return [f"{host}:{port}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qihse browse",
        description="QIHSE operator browser: web dashboard bridge "
                    "(default) or headless dump.")
    parser.add_argument("--node", action="append", default=[], metavar="HOST:PORT",
                        help="seed node (repeatable; the bridge only ever "
                             "connects to explicitly seeded nodes)")
    parser.add_argument("--port", type=int, default=8090,
                        help="bridge listen port (default 8090; loopback only)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="loopback bind address (non-loopback is refused)")
    parser.add_argument("--extra-actions", default=None, metavar="FILE",
                        help="operator-authored JSON allowlist extension "
                             "(additional touch-gated commands; validated "
                             "and audited like built-ins; SHUTDOWN/DEBUG/"
                             "CONFIG/FLUSH* are refused)")
    parser.add_argument("--qkp-identity-dir", default=None, metavar="DIR",
                        help="QKP1 sealed transport: qihse_keygen output "
                             "directory; lets the bridge reach --pqc-require "
                             "nodes (all RESP traffic rides sealed frames)")
    parser.add_argument("--qkp-trusted-pub", action="append", default=[],
                        metavar="PEM",
                        help="server ML-DSA-87 public key to trust (repeatable)")
    parser.add_argument("--credentials", default="browser-credentials.json",
                        help="WebAuthn credential store path (public keys only)")
    parser.add_argument("--require-login", action="store_true",
                        help="per-principal mode: password (+WebAuthn) login "
                             "per session. DEFAULT is operator-context: no "
                             "login wall — the bridge authenticates once at "
                             "startup from --password/QIHSE_OPERATOR_PASSWORD "
                             "and only guarded actions need a FIDO touch")
    parser.add_argument("--password", default=None,
                        help="operator credential for operator-context mode "
                             "(default: QIHSE_OPERATOR_PASSWORD)")
    parser.add_argument("--allow-password-only", action="store_true",
                        help="with --require-login: permit single-factor "
                             "password logins for users with no enrolled "
                             "credential (break-glass; fail-closed default)")
    parser.add_argument("--no-require-webauthn", action="store_true",
                        help="alias of --allow-password-only")
    # headless mode
    parser.add_argument("--dump", metavar="MODE",
                        choices=["overview", "cluster", "federation", "keys"],
                        help="headless dump (no HTTP, no WebAuthn) and exit")
    parser.add_argument("--user", default="GODMODE_OP",
                        help="principal for --dump")
    parser.add_argument("--pattern", default="*",
                        help="key pattern for --dump keys")
    args = parser.parse_args(argv)

    from .fleet import NodeSpec, parse_node_arg

    raw_nodes = list(args.node) or _nodes_from_env()
    if not raw_nodes:
        print("no seed nodes: pass --node host:port "
              "(or set QIHSE_NODE0_HOST/PORT)", file=sys.stderr)
        return 2
    try:
        nodes = [parse_node_arg(n) for n in raw_nodes]
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.dump:
        from .dump import run_dump
        return run_dump(nodes, args.user, args.password, args.dump,
                        pattern=args.pattern,
                        qkp_identity_dir=args.qkp_identity_dir,
                        qkp_trusted_pubs=args.qkp_trusted_pub or None)

    import os as _os
    from .bridge import serve
    allow_password_only = args.allow_password_only or args.no_require_webauthn
    operator_password = args.password or \
        _os.environ.get("QIHSE_OPERATOR_PASSWORD")
    serve(nodes, port=args.port, bind=args.bind,
          require_webauthn=not allow_password_only,
          allow_password_only=allow_password_only,
          credentials_path=args.credentials,
          mode="login" if args.require_login else "operator",
          operator_password=operator_password,
          extra_actions=args.extra_actions,
          qkp_identity_dir=args.qkp_identity_dir,
          qkp_trusted_pubs=args.qkp_trusted_pub or None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
