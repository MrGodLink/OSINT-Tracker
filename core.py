#!/usr/bin/env python3
#
# =============================================================================
#  Project      : OSINT Tracker
#  Description  : Core engine (Certificate Transparency + reverse-IP pivot)
#  Author       : Raffaele Catapano
#  License      : MIT (see LICENSE)
#  Created on   : 13/11/2026
#  Updated on   : 13/11/2026
#  Version      : 1.5.0
#
#  Copyright (c) 2026 Raffaele Catapano
#  Released under the MIT License - see the LICENSE file for details.
#  SPDX-License-Identifier: MIT
# =============================================================================
"""Qt-free engine.

The engine never prints and never translates: it reports progress through an
``emit(level, key, **kwargs)`` callback, and the GUI turns each ``key`` into a
message in the active language (see ``i18n.py``). This keeps the logic fully
testable offline.
"""
from __future__ import annotations

import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import quote, urlparse

import requests

APP_NAME = "OSINT Tracker"
APP_VERSION = "1.5.0"
APP_AUTHOR = "Raffaele Catapano"

CT_URL = "https://crt.sh/"
REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/"

CT_TIMEOUT = (10, 45)   # (connect, read) - crt.sh can be slow on big orgs
IP_TIMEOUT = (10, 15)
TLS_TIMEOUT = 6
MAX_RETRIES = 3
BACKOFF_HTTP = 5        # seconds * attempt
BACKOFF_NET = 4
RETRY_STATUS = {429, 502, 503, 504}

# Real CDN / cloud providers only - NOT Certificate Authorities.
CDN_CLOUD_ORGS = (
    "amazon", "aws", "cloudflare", "akamai", "fastly",
    "google cloud", "microsoft azure", "oracle cloud",
)
CDN_IP_INDICATORS = (
    "awsglobalaccelerator", "cloudflare", "akamai", "fastly",
    "azureedge", "compute.amazonaws.com",
)

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$"
)
ORG_RE = re.compile(r"O=([^,/]+)")

Emit = Callable[..., None]


class Cancelled(Exception):
    """Raised inside the engine when the user cancels the scan."""


@dataclass
class ScanResult:
    target: str
    is_domain: bool
    domains: list[str] = field(default_factory=list)   # everything found
    related: list[str] = field(default_factory=list)   # everything but the target
    org_name: Optional[str] = None
    org_expanded: bool = False
    ip: Optional[str] = None
    ip_pivot_used: bool = False
    network_error: bool = False
    elapsed: float = 0.0


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def _noop(level: str, key: str, **kw: Any) -> None:
    pass


def _check(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise Cancelled()


def _sleep(cancel: threading.Event, seconds: float) -> None:
    """Interruptible sleep: wakes up immediately when the scan is cancelled."""
    if cancel.wait(seconds):
        raise Cancelled()


def make_session() -> requests.Session:
    session = requests.Session()  # keep-alive: faster repeated crt.sh calls
    session.headers.update({
        "User-Agent": f"{APP_NAME.replace(' ', '-')}/{APP_VERSION}",
        "Accept": "application/json, text/plain;q=0.9, */*;q=0.5",
    })
    return session


def normalize_target(raw: str) -> str:
    """Trim input; turn URLs into hostnames; lowercase real domains."""
    t = (raw or "").strip()
    if "://" in t:
        host = urlparse(t).hostname
        if host:
            t = host
    t = t.strip().strip("/")
    if is_domain_target(t.rstrip(".")):
        return t.rstrip(".").lower()
    return t


def is_domain_target(target: str) -> bool:
    return bool(DOMAIN_RE.match(target))


def is_cdn_org(name: str) -> bool:
    n = name.lower()
    return any(c in n for c in CDN_CLOUD_ORGS)


def _clean_name(raw: Optional[str]) -> str:
    """Lowercase, drop '*.' wildcards, discard e-mails and non-hostnames."""
    n = (raw or "").strip().lower()
    if n.startswith("*."):
        n = n[2:]
    return n if HOSTNAME_RE.match(n) else ""


def extract_names(certs: list) -> set[str]:
    names: set[str] = set()
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        candidates = [cert.get("common_name") or ""]
        candidates += (cert.get("name_value") or "").split("\n")
        for raw in candidates:
            n = _clean_name(raw)
            if n:
                names.add(n)
    return names


def is_only_self_and_subdomains(domains, target: str) -> bool:
    """True when results are ONLY the target and its direct subdomains."""
    t = target.lower()
    return all(d == t or d.endswith("." + t) for d in domains)


# --------------------------------------------------------------------------- #
#  Network
# --------------------------------------------------------------------------- #
def retry_request(session, url: str, cancel: threading.Event, emit: Emit = _noop,
                  max_retries: int = MAX_RETRIES, timeout=CT_TIMEOUT):
    """GET url and return parsed JSON, or None after the retries are exhausted."""
    for attempt in range(max_retries):
        _check(cancel)
        last = attempt == max_retries - 1
        try:
            res = session.get(url, timeout=timeout)
            if res.status_code == 200:
                try:
                    return res.json()
                except ValueError:  # crt.sh sometimes answers 200 with HTML when overloaded
                    wait = (attempt + 1) * BACKOFF_HTTP
                    if not last:
                        emit("warn", "log.bad_json", wait=wait, n=attempt + 1, max=max_retries)
                        _sleep(cancel, wait)
                    continue
            if res.status_code in RETRY_STATUS:
                wait = (attempt + 1) * BACKOFF_HTTP
                if not last:
                    emit("warn", "log.retry_http", code=res.status_code, wait=wait,
                         n=attempt + 1, max=max_retries)
                    _sleep(cancel, wait)
                continue
            emit("err", "log.http_err", code=res.status_code)
            return None
        except requests.exceptions.RequestException as e:
            wait = (attempt + 1) * BACKOFF_NET
            if not last:
                emit("warn", "log.retry_error", name=type(e).__name__, wait=wait,
                     n=attempt + 1, max=max_retries)
                _sleep(cancel, wait)
    return None


def _org_from_subject(subject: Optional[str]) -> Optional[str]:
    m = ORG_RE.search(subject or "")
    return m.group(1).strip() if m else None


def _find_org_in_certs(certs: list) -> Optional[str]:
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        org = _org_from_subject(cert.get("subject_name"))
        if org and len(org) > 2 and not is_cdn_org(org):
            return org
    return None


def fetch_org_via_tls(host: str, cancel: threading.Event) -> Optional[str]:
    """Read the Organization of the live TLS certificate (one fast handshake).

    crt.sh's JSON output does not always include the certificate subject, so
    this is the reliable way to discover the owning organization.
    """
    _check(cancel)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except (OSError, ssl.SSLError, ValueError):
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "organizationName":
                org = str(value).strip()
                if len(org) > 2 and not is_cdn_org(org):
                    return org
    return None


def get_domains_from_ct(session, target: str, is_domain: bool, expand_org: bool,
                        cancel: threading.Event, emit: Emit = _noop):
    """Return (names, org_name, org_expanded, ok)."""
    param = "q" if is_domain else "O"
    url = f"{CT_URL}?{param}={quote(target)}&output=json"
    emit("muted", "log.query", url=url)

    data = retry_request(session, url, cancel, emit)
    if data is None:
        emit("err", "log.ct_failed")
        return set(), None, False, False
    if not isinstance(data, list):
        data = []

    org_name, expanded = None, False
    if is_domain and expand_org:
        org = _find_org_in_certs(data)
        key = "log.org_extracted"
        if not org:
            org, key = fetch_org_via_tls(target, cancel), "log.org_tls"
        if org:
            emit("ok", key, org=org)
            org_url = f"{CT_URL}?O={quote(org)}&output=json"
            org_data = retry_request(session, org_url, cancel, emit)
            if isinstance(org_data, list) and org_data:
                data, org_name, expanded = org_data, org, True
        else:
            emit("muted", "log.org_none")

    names = extract_names(data)
    emit("info", "log.ct_count", n=len(names))
    return names, org_name, expanded, True


def get_domains_from_ip(session, target: str, cancel: threading.Event, emit: Emit = _noop):
    """Return (ip, domains) using a reverse-IP lookup; CDN/cloud IPs are ignored."""
    emit("muted", "log.ip_fallback")
    try:
        ip = socket.gethostbyname(target)
    except OSError as e:
        emit("err", "log.dns_error", err=str(e))
        return None, []
    emit("info", "log.ip_resolved", ip=ip)
    _check(cancel)

    try:
        res = session.get(f"{REVERSE_IP_URL}?q={ip}", timeout=IP_TIMEOUT)
    except requests.exceptions.RequestException as e:
        emit("err", "log.dns_error", err=type(e).__name__)
        return ip, []

    text = res.text if res.status_code == 200 else ""
    if "api count exceeded" in text.lower():
        emit("warn", "log.rate_limited")
        return ip, []
    if res.status_code == 200 and "error" not in text.lower():
        raw = [d for d in (_clean_name(line) for line in text.splitlines()) if d]
        if not raw:
            emit("warn", "log.no_reverse")
            return ip, []
        clean = [d for d in raw if not any(c in d for c in CDN_IP_INDICATORS)]
        if clean:
            emit("ok", "log.ip_found", n=len(clean))
            return ip, clean
        emit("warn", "log.cdn_ip")
    else:
        emit("warn", "log.no_reverse")
    return ip, []


# --------------------------------------------------------------------------- #
#  Orchestration
# --------------------------------------------------------------------------- #
def run_scan(target: str, *, expand_org: bool = True, ip_fallback: bool = True,
             cancel: Optional[threading.Event] = None, emit: Optional[Emit] = None,
             session=None) -> ScanResult:
    cancel = cancel or threading.Event()
    emit = emit or _noop
    own_session = session is None
    session = session or make_session()
    start = time.monotonic()

    result = ScanResult(target=target, is_domain=is_domain_target(target))
    try:
        names, org, expanded, ok = get_domains_from_ct(
            session, target, result.is_domain, expand_org, cancel, emit)
        result.org_name, result.org_expanded = org, expanded
        domains = set(names)

        if result.is_domain and ip_fallback and is_only_self_and_subdomains(domains, target):
            emit("warn", "log.only_subdomains")
            ip, ip_domains = get_domains_from_ip(session, target, cancel, emit)
            result.ip = ip
            if ip_domains:
                result.ip_pivot_used = True
                domains |= set(ip_domains)

        result.domains = sorted(domains)
        t = target.lower()
        result.related = [d for d in result.domains if d != t]
        result.network_error = (not ok) and not result.related
    finally:
        if own_session:
            session.close()
        result.elapsed = time.monotonic() - start
    return result
