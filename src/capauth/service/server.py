"""CapAuth Verification Service — standalone server launcher.

Usage:
    capauth-service                    # Start on 127.0.0.1:8420 (loopback)
    capauth-service --port 9000        # Custom port
    CAPAUTH_SERVICE_HOST=100.x.y.z capauth-service  # Bind a tailnet iface
    CAPAUTH_SERVICE_ID=myserver capauth-service  # Custom service ID

Security: the default bind is loopback (127.0.0.1). This is a PDP / auth
decision point and must never sit on a public interface; behind Traefik in
cluster mode or reached over the tailnet, set --host / CAPAUTH_SERVICE_HOST
to that interface explicitly. A 0.0.0.0 bind is warned about at startup.

Environment variables:
    CAPAUTH_SERVICE_HOST       Bind address (default: 127.0.0.1)
    CAPAUTH_SERVICE_ID       — Service identifier (default: capauth.local)
    CAPAUTH_SERVER_KEY_ARMOR — Server's PGP private key for signing challenges
    CAPAUTH_SERVER_KEY_PASSPHRASE — Passphrase for the server key
    CAPAUTH_REQUIRE_APPROVAL — Require admin approval for new keys (true/false)
    CAPAUTH_DB_PATH          — SQLite database path (default: ~/.capauth/service/keys.db)
    CAPAUTH_ADMIN_TOKEN      — Bearer token for admin API access
    CAPAUTH_BASE_URL         — Public base URL for OIDC discovery
"""

from __future__ import annotations

import click


@click.command()
@click.option("--host", envvar="CAPAUTH_SERVICE_HOST", default="127.0.0.1",
              help="Bind address (default: loopback; env CAPAUTH_SERVICE_HOST).")
@click.option("--port", default=8420, type=int, help="Listen port.")
@click.option("--reload", "do_reload", is_flag=True, help="Auto-reload on code changes.")
def main(host: str, port: int, do_reload: bool) -> None:
    """Start the CapAuth Verification Service.

    Passwordless PGP authentication for Nextcloud, Forgejo, and any app.
    """
    try:
        import uvicorn
    except ImportError:
        click.echo("Error: uvicorn not installed. Run: pip install capauth[service]")
        raise SystemExit(1)

    if host in ("0.0.0.0", "::", ""):
        click.echo(
            f"WARNING: binding CapAuth (a PDP / auth decision point) to {host!r} "
            "exposes it on ALL interfaces. Prefer 127.0.0.1 or a specific tailnet "
            "address behind the :443 ingress (UNIFIED_INGRESS_STANDARD).",
            err=True,
        )
    click.echo(f"CapAuth Verification Service starting on {host}:{port}")
    click.echo("Endpoints:")
    click.echo(f"  POST http://{host}:{port}/capauth/v1/challenge")
    click.echo(f"  POST http://{host}:{port}/capauth/v1/verify")
    click.echo(f"  GET  http://{host}:{port}/capauth/v1/status")
    click.echo(f"  GET  http://{host}:{port}/.well-known/openid-configuration")

    uvicorn.run(
        "capauth.service.app:app",
        host=host,
        port=port,
        reload=do_reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
