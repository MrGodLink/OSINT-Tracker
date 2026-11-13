# OSINT Tracker

**English** | [Italiano](README.it.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-1.5.0-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

**Find related domains through Certificate Transparency.**
A cross-platform desktop tool that pivots on `crt.sh` and reverse-IP lookups to surface the full domain footprint of a target.

---

## Overview

OSINT Tracker takes a domain or an organization name and returns the set of domains associated with it, using three complementary discovery channels:

1. **Certificate Transparency** »  queries `crt.sh` for every certificate ever issued to the target (or to the organization name you typed).
2. **Organization expansion** »  extracts the `O=` (organization) field from the certificate, falling back to a live TLS handshake, then re-queries `crt.sh` with that organization name to pull every sibling domain.
3. **Reverse-IP pivot** »  when the first two steps return only the target and its direct subdomains, resolves the IP and queries `api.hackertarget.com/reverseiplookup` to find other sites hosted on the same server.

The engine is Qt-free, designed to be testable offline, and reports progress through a structured `emit(level, key, **kwargs)` callback that the GUI translates on the fly.

---

## Features

- **Dual input modes** »  domain (`example.com`) or organization name (`Acme Corp`). URLs are also accepted and reduced to their hostname.
- **Live TLS org extraction** »  reads the real `organizationName` from the certificate served on port 443, because `crt.sh` JSON output does not always include the certificate subject.
- **CDN-aware filtering** »  ignores AWS / Cloudflare / Akamai / Fastly / Azure / Google Cloud / Oracle Cloud noise, both at organization level and at IP level.
- **Resilient networking** »  automatic retry with progressive backoff on `429`, `502`, `503`, `504`, network errors and malformed JSON responses.
- **Cancellable scans** »  every network call and every sleep is interruptible via a `threading.Event`.
- **Dark UI** »  custom PySide6 stylesheet, monospaced activity log, filterable result list, context menu, keyboard shortcuts.
- **Bilingual** »  Italian / English, auto-detected from the system locale and persisted via `QSettings`.
- **Export** »  plain text (`.txt`, one domain per line) or CSV (`.csv`, with a `domain` header).
- **Zero external assets** »  the application icon is generated at runtime as SVG (XML); no image files are shipped.

---

## Requirements

- **Python 3.10+**
- Dependencies:
  - [`PySide6`](https://doc.qt.io/qtforpython/) »  Qt 6 bindings (GUI and SVG rendering)
  - [`requests`](https://requests.readthedocs.io/) »  HTTP client

No system packages, no Qt Designer files, no binary assets.

> **Linux note:** on some distributions (e.g. Ubuntu/Debian) Qt 6 may fail to start with an error about the `xcb` platform plugin. Installing `libxcb-cursor0` usually fixes it:
> `sudo apt install libxcb-cursor0`

---

## Installation

```bash
git clone https://github.com/MrGodLink/osint-tracker.git
cd osint-tracker
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

`requirements.txt`:

```
PySide6>=6.6,<7
requests>=2.31
```

---

## Usage

```bash
python main.py
```

1. Type a domain (`example.com`) or an organization name in the input field.
2. Toggle the options:
   - **Expand by organization** »  find the owning organization and list every domain registered to it.
   - **IP fallback** »  if only direct subdomains are found, pivot on the resolved IP.
3. Press **Enter** or click **Start scan**.
4. Results appear in the list; filter, copy, or export them as needed.

### Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Start scan |
| `Esc` | Cancel scan |
| `Ctrl+L` | Focus input |
| `Ctrl+F` | Focus filter |
| `Ctrl+E` | Export results |
| `Ctrl+C` (in list) | Copy selected domains |

---

## Architecture

```
osint-tracker/
├── main.py            # PySide6 GUI, theming, icon generation, worker thread
├── core.py            # Qt-free engine: crt.sh, TLS org extraction, reverse-IP
├── i18n.py            # Bilingual string table (IT / EN)
├── requirements.txt
├── LICENSE
├── README.md
└── README.it.md
```

### `core.py` »  the engine

- `run_scan(target, expand_org, ip_fallback, cancel, emit)` → `ScanResult`
- `get_domains_from_ct(...)` »  queries `crt.sh`, optionally expands by organization.
- `fetch_org_via_tls(host, cancel)` »  one-shot TLS handshake to read the organization.
- `get_domains_from_ip(...)` »  resolves the IP, queries HackerTarget, filters CDN indicators.
- `retry_request(...)` »  shared retry logic with backoff and cancellation support.
- The engine never prints and never translates: the GUI is responsible for presentation.

### `main.py` »  the GUI

- `ScanWorker` »  `QObject` running `core.run_scan` in a daemon thread; reports back through Qt signals.
- `MainWindow` »  builds the UI, wires signals, handles shortcuts, manages state.
- `build_icon_svg()` »  generates the radar icon as XML at runtime; rendered at 7 sizes (16 → 256 px) via `QSvgRenderer`.
- `build_stylesheet()` »  injects the color palette into the QSS template.

### `i18n.py` »  translations

- `TRANSLATIONS` dict with two language blocks (`en`, `it`); every key must exist in `en`.
- `tr(key, **kw)` »  formats the string, falls back to English, never raises.
- `detect_language(locale)` »  maps `it_IT`, `en-US`, etc. to a supported code.

To add a language, add a new block to `TRANSLATIONS` and an entry to `LANGUAGES` in `i18n.py`.

---

## Data sources

| Source | Endpoint | Purpose |
|--------|----------|---------|
| crt.sh | `https://crt.sh/?q=...&output=json` | Certificate Transparency logs |
| HackerTarget | `https://api.hackertarget.com/reverseiplookup/?q=...` | Reverse-IP lookup |
| Live TLS | port 443 via the `ssl` stdlib | Organization extraction |

No API keys required. Transient errors are retried automatically; the free HackerTarget quota is limited, and when it is exhausted the tool reports it in the activity log and carries on without the reverse-IP results.

---

## Privacy and responsible use

- The target you type is sent to third-party services (`crt.sh` and, if the IP fallback is used, HackerTarget).
- The **Expand by organization** step opens a direct TLS connection to the target on port 443, and the **IP fallback** resolves its DNS name. These are the only requests that reach the target itself.
- Use this tool only on domains and organizations you own or are authorized to investigate. You are responsible for complying with the laws and terms of service that apply to you.

---

## Credits

Created by **Raffaele Catapano** »  [github.com/MrGodLink](https://github.com/MrGodLink)

If you reuse, modify or redistribute this project, please keep the copyright notice and credit the original author, as required by the MIT License.

Bug reports and ideas are welcome in the [issue tracker](https://github.com/MrGodLink/osint-tracker/issues).

## License

The source code is released under the MIT License »  see [LICENSE](LICENSE).

OSINT Tracker depends on [PySide6](https://doc.qt.io/qtforpython/), licensed under the LGPLv3 (or a Qt commercial license). It is installed separately (via `pip` or your distribution). If you distribute a bundled executable (for example built with PyInstaller), you must also comply with the LGPL terms for PySide6 and Qt.
