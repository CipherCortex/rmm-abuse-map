"""Parse ScreenConnect / ConnectWise Control client command lines and URLs."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

# Common patterns seen in trojanized ScreenConnect / Control clients:
#   ScreenConnect.Client.exe "?e=Access&y=Guest&h=evil.example.com&p=443&..."
#   msiexec ... /i https://.../Bin/...msi
#   h=<relay host>  e=<mode>  k=<key>  s=<session>  i=<instance>

_H_PARAM = re.compile(r"(?:^|[?&\"'\s])h=([A-Za-z0-9._:-]+)", re.I)
_E_PARAM = re.compile(r"(?:^|[?&\"'\s])e=([A-Za-z0-9._-]+)", re.I)
_P_PARAM = re.compile(r"(?:^|[?&\"'\s])p=(\d{2,5})", re.I)
_K_PARAM = re.compile(r"(?:^|[?&\"'\s])k=([A-Za-z0-9+/=_-]+)", re.I)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_MSI = re.compile(r"(?i)([\w.-]+\.msi)")
_SC_EXE = re.compile(r"(?i)(ScreenConnect(?:\.Client)?\.exe|ConnectWiseControl\.Client\.exe)")


@dataclass
class RelayObservation:
    source: str
    relay_host: str | None = None
    relay_port: int | None = None
    mode: str | None = None  # e= Access / Support / Meeting / Guest
    key_hint: str | None = None
    urls: list[str] = field(default_factory=list)
    msi_names: list[str] = field(default_factory=list)
    binary_hint: str | None = None
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _first(rx: re.Pattern[str], text: str) -> str | None:
    m = rx.search(text)
    return m.group(1) if m else None


def parse_cmdline(text: str, *, source: str = "cmdline") -> RelayObservation:
    """Extract relay indicators from a process command line or installer URL."""
    text = unquote(text.strip())
    obs = RelayObservation(source=source, raw=text)

    obs.relay_host = _first(_H_PARAM, text)
    mode = _first(_E_PARAM, text)
    if mode:
        obs.mode = mode
    port = _first(_P_PARAM, text)
    if port:
        obs.relay_port = int(port)
    key = _first(_K_PARAM, text)
    if key:
        obs.key_hint = key[:32]

    urls = _URL.findall(text)
    obs.urls = urls
    for u in urls:
        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        if not obs.relay_host and "h" in qs:
            obs.relay_host = qs["h"][0]
        if not obs.mode and "e" in qs:
            obs.mode = qs["e"][0]
        if not obs.relay_port and "p" in qs:
            try:
                obs.relay_port = int(qs["p"][0])
            except ValueError:
                pass
        # Self-hosted Control often: https://relay.example.com/Bin/...
        if not obs.relay_host and parsed.hostname:
            path = (parsed.path or "").lower()
            if "/bin/" in path or "screenconnect" in path or "connectwise" in path:
                obs.relay_host = parsed.hostname
                if parsed.port:
                    obs.relay_port = parsed.port

    obs.msi_names = list({m for m in _MSI.findall(text)})
    exe = _SC_EXE.search(text)
    if exe:
        obs.binary_hint = exe.group(1)

    return obs


def cluster_by_relay(observations: list[RelayObservation]) -> dict[str, list[dict[str, Any]]]:
    """Group observations by normalized relay host (unknown bucket if missing)."""
    clusters: dict[str, list[dict[str, Any]]] = {}
    for obs in observations:
        key = (obs.relay_host or "unknown").lower().rstrip(".")
        clusters.setdefault(key, []).append(obs.to_dict())
    return dict(sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0])))
