"""Scope parsing and enforcement, independent from orchestration and models."""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from sentinel.models import Limits, TargetScope


class ScopeError(ValueError):
    """Raised before an out-of-policy request can be made."""


def _scalar(value: str) -> object:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        return [_scalar(item) for item in value[1:-1].split(",") if item.strip()]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value.strip("\"'")


def _parse_simple_yaml(text: str) -> dict[str, object]:
    """Parse the deliberately small, documented scope-file YAML subset.

    JSON is also accepted. A full YAML engine is intentionally not bundled offline.
    """
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded: dict[str, object] = {}
        current_list: list[object] | None = None
        current_mapping: dict[str, object] | None = None
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()
            if stripped.startswith("- "):
                if current_list is None:
                    raise ScopeError("list item without a list key")
                current_list.append(_scalar(stripped[2:]))
                continue
            if ":" not in stripped:
                raise ScopeError(f"invalid scope line: {raw_line}")
            key, raw_value = stripped.split(":", 1)
            value = raw_value.strip()
            if indent == 0:
                current_mapping = None
                if value:
                    loaded[key] = _scalar(value)
                    current_list = None
                else:
                    loaded[key] = [] if key in {"targets", "allowed_hosts"} else {}
                    current_list = loaded[key] if isinstance(loaded[key], list) else None
                    current_mapping = loaded[key] if isinstance(loaded[key], dict) else None
            elif indent == 2 and current_mapping is not None:
                current_mapping[key] = _scalar(value)
            else:
                raise ScopeError(f"unsupported scope indentation: {raw_line}")
    if not isinstance(loaded, dict):
        raise ScopeError("scope document must be a mapping")
    return loaded


def load_scope(path: Path) -> TargetScope:
    data = _parse_simple_yaml(path.read_text(encoding="utf-8"))
    try:
        limits_data = data.get("limits", {})
        if not isinstance(limits_data, dict):
            raise TypeError("limits must be a mapping")
        limits = Limits(**limits_data)
        scope = TargetScope(
            targets=tuple(str(item) for item in data["targets"]),
            allowed_hosts=tuple(str(item).lower() for item in data["allowed_hosts"]),
            allowed_schemes=tuple(str(item).lower() for item in data.get("allowed_schemes", ["https"])),
            allowed_ports=tuple(int(item) for item in data.get("allowed_ports", [443])),
            allowed_paths=tuple(str(item) for item in data.get("allowed_paths", ["/"])),
            mode=str(data.get("mode", "passive")),
            limits=limits,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ScopeError(f"invalid scope: {exc}") from exc
    if scope.mode != "passive":
        raise ScopeError("only passive mode is supported")
    if not scope.targets or not scope.allowed_hosts:
        raise ScopeError("targets and allowed_hosts cannot be empty")
    for target in scope.targets:
        validate_url(target, scope, resolve_dns=False)
    return scope


def normalize_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ScopeError("URL must have a hostname and no embedded credentials")
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower().rstrip(".")
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    if port is None:
        raise ScopeError("unsupported URL scheme")
    netloc = f"{hostname}:{port}" if (scheme, port) not in {("https", 443), ("http", 80)} else hostname
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global


def validate_url(url: str, scope: TargetScope, *, resolve_dns: bool = True) -> str:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme not in scope.allowed_schemes:
        raise ScopeError(f"scheme '{parsed.scheme}' is out of scope")
    if host not in scope.allowed_hosts:
        raise ScopeError(f"host '{host}' is out of scope")
    if port not in scope.allowed_ports:
        raise ScopeError(f"port '{port}' is out of scope")
    if not any(parsed.path.startswith(prefix) for prefix in scope.allowed_paths):
        raise ScopeError(f"path '{parsed.path}' is out of scope")
    if resolve_dns:
        resolve_public_address(host, port)
    return normalized


def resolve_public_address(host: str, port: int) -> str:
    """Resolve a hostname once and return a vetted address for connection pinning.

    Rejecting a mixed public/private answer is intentional: accepting one public answer
    would leave room for DNS rebinding to an internal service.
    """
    try:
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise ScopeError(f"could not resolve {host}") from exc
    if not addresses or any(not _is_public_ip(address) for address in addresses):
        raise ScopeError("target DNS resolves to a non-public or unsafe address")
    return addresses[0]
