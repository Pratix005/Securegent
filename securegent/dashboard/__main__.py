"""
Securegent dashboard.

  python -m securegent.dashboard            # then open the printed link
  python -m securegent.dashboard --open     # opens your browser too

Shows the live audit log, lets you approve/deny actions that need a human (run the
MCP proxy with --approvals), and has a kill switch that stops every agent tool call.
"""

import argparse
import sys
import webbrowser
from pathlib import Path

from ..approvals import DEFAULT_STATE_DIR
from .server import DashboardState, create_server


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m securegent.dashboard",
                                description="Local web dashboard for Securegent.")
    p.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR),
                   help=f"folder shared with the MCP proxy (default: {DEFAULT_STATE_DIR})")
    p.add_argument("--audit", help="audit log to show (default: <state-dir>/audit.jsonl)")
    p.add_argument("--kill-switch", help="kill-switch file (default: <state-dir>/KILL_SWITCH)")
    p.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default: 8765)")
    p.add_argument("--open", action="store_true", help="open the dashboard in your browser")
    args = p.parse_args(argv)

    state_dir = Path(args.state_dir)
    state = DashboardState(state_dir,
                           Path(args.audit) if args.audit else state_dir / "audit.jsonl",
                           Path(args.kill_switch) if args.kill_switch else state_dir / "KILL_SWITCH")
    try:
        server, token = create_server(state, args.port)
    except OSError as e:
        print(f"Can't start on port {args.port}: {e}. Try --port 8766.", file=sys.stderr)
        return 1

    url = f"http://127.0.0.1:{args.port}/#token={token}"
    print("Securegent dashboard running (only reachable from this computer)")
    print(f"  Open:  {url}")
    print("  The link contains a secret token. Don't share it. Ctrl+C to stop.")
    print(f"  Audit log: {state.audit.path}")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
