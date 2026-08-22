"""Syncthing-based public identity distribution for CapAuth.

Shares public profile material across cluster nodes while keeping private keys,
revocation certificates, keystores, backups, and passphrase files local. A
single private signer replicated to every node creates an unnecessarily broad
blast radius; service and node identities should be provisioned separately.

Usage:
    from capauth.sync import setup_syncthing_sync, is_sync_configured

    # After capauth init, offer to sync:
    if not is_sync_configured():
        setup_syncthing_sync()
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from . import resolve_capauth_home

logger = logging.getLogger(__name__)

FOLDER_ID = "capauth-identity"
FOLDER_LABEL = ".capauth"

# These rules live at the configured Syncthing folder root. The first two are
# the minimum policy enforced by capauth doctor estate; the others prevent
# common custody and runtime-secret files from being added later.
REQUIRED_SECRET_IGNORE_RULES = (
    "**/private.*",
    "**/root-revocation.asc",
    "**/*.passphrase",
    "**/passphrase.*",
    "**/*.env",
    "**/*.db",
    "**/*.db-*",
    "**/backups/",
)

# Syncthing config locations (in priority order)
_CONFIG_PATHS = [
    Path.home() / ".local" / "state" / "syncthing" / "config.xml",
    Path.home() / ".config" / "syncthing" / "config.xml",
]


def _find_syncthing_config() -> Optional[Path]:
    """Find the Syncthing config.xml on this host."""
    for p in _CONFIG_PATHS:
        if p.exists():
            return p
    return None


def _get_api_info() -> tuple[Optional[str], Optional[str]]:
    """Read the Syncthing API URL and key from config.xml.

    Returns:
        (base_url, api_key) or (None, None) if unavailable.
    """
    # Prefer env vars
    url = os.environ.get("SYNCTHING_URL")
    key = os.environ.get("SYNCTHING_API_KEY")
    if url and key:
        return url, key

    config_path = _find_syncthing_config()
    if config_path is None:
        return None, None

    try:
        tree = ET.parse(config_path)
        root = tree.getroot()
        gui = root.find("gui")
        if gui is not None:
            address = gui.findtext("address", "127.0.0.1:8384")
            apikey = gui.findtext("apikey", "")
            tls = gui.get("tls", "false") == "true"
            scheme = "https" if tls else "http"
            return f"{scheme}://{address}", apikey
    except (ET.ParseError, OSError) as exc:
        logger.debug("Failed to parse Syncthing config: %s", exc)

    return None, None


def is_syncthing_available() -> bool:
    """Check if Syncthing is installed and its config exists."""
    import shutil

    return shutil.which("syncthing") is not None and _find_syncthing_config() is not None


def is_sync_configured() -> bool:
    """Check if capauth-identity Syncthing folder already exists."""
    config_path = _find_syncthing_config()
    if config_path is None:
        return False

    try:
        tree = ET.parse(config_path)
        for folder in tree.getroot().findall("folder"):
            if folder.get("id") == FOLDER_ID:
                return True
    except (ET.ParseError, OSError):
        pass

    return False


def ensure_secret_material_ignored(capauth_dir: Path) -> Path:
    """Enforce secret-material exclusions at the actual Syncthing root.

    Existing user rules and comments are preserved. Only missing required
    rules are appended, using an atomic replace so a partial write cannot
    silently remove a protection.

    Returns:
        The .stignore path.
    """
    root = Path(capauth_dir).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    ignore_path = root / ".stignore"
    try:
        existing = ignore_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        existing = ""
    active = {
        line.strip()
        for line in existing.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    }
    missing = [rule for rule in REQUIRED_SECRET_IGNORE_RULES if rule not in active]
    if not missing:
        return ignore_path

    content = existing.rstrip()
    if content:
        content += "\n\n"
    content += "# CapAuth custody boundary: never replicate secret material\n"
    content += "\n".join(missing) + "\n"
    temporary = ignore_path.with_name(f".{ignore_path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(ignore_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return ignore_path


def get_known_devices() -> list[dict]:
    """Return all Syncthing devices from config.xml.

    Returns:
        List of dicts with 'id' and 'name' keys.
    """
    config_path = _find_syncthing_config()
    if config_path is None:
        return []

    try:
        tree = ET.parse(config_path)
        devices = []
        for dev in tree.getroot().findall("device"):
            devices.append(
                {
                    "id": dev.get("id", ""),
                    "name": dev.get("name", ""),
                }
            )
        return devices
    except (ET.ParseError, OSError):
        return []


def setup_syncthing_sync(
    capauth_dir: Optional[Path] = None,
    device_ids: Optional[list[str]] = None,
) -> bool:
    """Add the CapAuth home as a public-material Syncthing folder.

    If the Syncthing REST API is reachable, uses it. Otherwise falls
    back to editing config.xml directly. Required secret exclusions are written
    before the folder is registered; setup fails closed if that cannot be done.

    Args:
        capauth_dir: Path to the capauth home (default ~/.capauth/).
        device_ids: Optional list of device IDs to share with. If None,
            shares with all known Syncthing devices.

    Returns:
        True if the folder was added successfully.
    """
    capauth_path = resolve_capauth_home(capauth_dir)

    try:
        ensure_secret_material_ignored(capauth_path)
    except OSError as exc:
        logger.warning("Cannot enforce CapAuth Syncthing custody boundary: %s", exc)
        return False

    # Create .stfolder marker so Syncthing recognizes it
    (capauth_path / ".stfolder").touch(exist_ok=True)

    # Try REST API first
    base_url, api_key = _get_api_info()
    if base_url and api_key:
        try:
            return _setup_via_api(base_url, api_key, capauth_path, device_ids)
        except Exception as exc:
            logger.warning("REST API failed (%s), falling back to config.xml", exc)

    # Fall back to direct config.xml editing
    return _setup_via_config(capauth_path, device_ids)


def _setup_via_api(
    base_url: str,
    api_key: str,
    capauth_path: Path,
    device_ids: Optional[list[str]],
) -> bool:
    """Add the capauth folder via Syncthing REST API."""
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }

    # Get all devices if none specified
    if device_ids is None:
        req = urllib.request.Request(
            f"{base_url}/rest/config/devices",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            devices = json.loads(resp.read())
        device_ids = [d["deviceID"] for d in devices]

    device_list = [
        {"deviceID": did, "introducedBy": "", "encryptionPassword": ""} for did in device_ids
    ]

    folder = {
        "id": FOLDER_ID,
        "label": FOLDER_LABEL,
        "path": str(capauth_path),
        "type": "sendreceive",
        "rescanIntervalS": 60,
        "fsWatcherEnabled": True,
        "fsWatcherDelayS": 10,
        "ignorePerms": False,
        "autoNormalize": True,
        "devices": device_list,
        "minDiskFree": {"value": 1, "unit": "%"},
    }

    data = json.dumps(folder).encode()
    req = urllib.request.Request(
        f"{base_url}/rest/config/folders",
        data=data,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Syncthing folder added via API: %s", resp.status)
            return True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        if "already exists" in body:
            logger.info("Syncthing folder already exists")
            return True
        logger.warning("API error: %s %s", exc.code, body)
        return False


def _setup_via_config(
    capauth_path: Path,
    device_ids: Optional[list[str]],
) -> bool:
    """Add the capauth folder by editing config.xml directly."""
    config_path = _find_syncthing_config()
    if config_path is None:
        logger.warning("No Syncthing config.xml found")
        return False

    try:
        tree = ET.parse(config_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse config.xml: %s", exc)
        return False

    # Check if folder already exists
    for folder in root.findall("folder"):
        if folder.get("id") == FOLDER_ID:
            logger.info("Syncthing folder already exists in config.xml")
            return True

    # Collect device IDs
    if device_ids is None:
        device_ids = [d.get("id", "") for d in root.findall("device") if d.get("id")]

    # Add folder element
    folder_elem = ET.SubElement(root, "folder")
    folder_elem.set("id", FOLDER_ID)
    folder_elem.set("label", FOLDER_LABEL)
    folder_elem.set("path", str(capauth_path))
    folder_elem.set("type", "sendreceive")
    folder_elem.set("rescanIntervalS", "60")
    folder_elem.set("fsWatcherEnabled", "true")
    folder_elem.set("fsWatcherDelayS", "10")
    folder_elem.set("ignorePerms", "false")
    folder_elem.set("autoNormalize", "true")

    for did in device_ids:
        dev_ref = ET.SubElement(folder_elem, "device")
        dev_ref.set("id", did)
        dev_ref.set("introducedBy", "")

    min_disk = ET.SubElement(folder_elem, "minDiskFree")
    min_disk.set("unit", "%")
    min_disk.text = "1"

    tree.write(config_path, xml_declaration=True, encoding="unicode")
    logger.info("Syncthing folder added to config.xml")
    return True
