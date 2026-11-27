#!/usr/bin/env python3
"""Operator CLI for engagement-scoped authentication identities and sessions."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.auth import AuthenticationManager, SessionStore
from core.auth.broker_transport import BrokerAuthTransport
from core.orchestration import Workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("genkey")
    sub.add_parser("rotate-keys", help="re-encrypt every stored session under the FIRST key of "
                                       "WITHERHOARD_AUTH_VAULT_KEY (comma-separated: new key first, old keys after)")
    register = sub.add_parser("register")
    register.add_argument("--engagement-id", required=True)
    register.add_argument("--identity-id", required=True)
    register.add_argument("--adapter", required=True,
                          choices=["form", "oauth2", "oidc", "cookie", "jwt", "api_key", "browser"])
    register.add_argument("--config", required=True, help="JSON config containing env-var references only")
    auth = sub.add_parser("authenticate")
    auth.add_argument("--engagement-id", required=True)
    auth.add_argument("--identity-id", required=True)
    auth.add_argument("--scope-asset", action="append", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--engagement-id", required=True)
    listing.add_argument("--identity-id", required=True)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--engagement-id", required=True)
    revoke.add_argument("--identity-id", required=True)
    revoke.add_argument("--session-id", required=True)
    args = parser.parse_args()

    if args.command == "genkey":
        from cryptography.fernet import Fernet
        print(Fernet.generate_key().decode())
        return

    with Workflow(args.db) as workflow:
        store = SessionStore(workflow.store.db_path)
        try:
            manager = AuthenticationManager(store, args.engagement_id) if hasattr(args, "engagement_id") else None
            if args.command == "register":
                config = json.loads(Path(args.config).read_text(encoding="utf-8"))
                manager.register_identity(args.identity_id, args.adapter, config)
                print(json.dumps({"identity_id": args.identity_id, "adapter": args.adapter, "registered": True}))
            elif args.command == "authenticate":
                identity = store.identity(args.engagement_id, args.identity_id)
                transport = None
                if identity["adapter"] in {"form", "oauth2", "oidc"}:
                    transport = BrokerAuthTransport(
                        workflow, args.engagement_id, args.scope_asset,
                        identity["config"].get("base_url", ""),
                    )
                manager = AuthenticationManager(store, args.engagement_id, transport=transport)
                session_id = manager.authenticate(args.identity_id, transport=transport)
                print(json.dumps({"identity_id": args.identity_id, "session_id": session_id,
                                  "authenticated": True}))
            elif args.command == "list":
                current = store.latest(args.engagement_id, args.identity_id)
                print(json.dumps({"identity_id": args.identity_id, "latest_session_id": current}))
            elif args.command == "revoke":
                manager.revoke(args.session_id, args.identity_id)
                print(json.dumps({"session_id": args.session_id, "revoked": True}))
            elif args.command == "rotate-keys":
                # All-or-nothing: one undecryptable row aborts the transaction and nothing is rewritten.
                print(json.dumps({"sessions_re_encrypted": store.rotate_keys()}))
        finally:
            store.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
