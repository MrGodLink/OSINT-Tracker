#!/usr/bin/env python3
#
# =============================================================================
#  Project      : OSINT Tracker
#  Description  : Bilingual strings (Italian / English) and language helpers
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
"""All user-visible text lives here. To add a language, add a new block to
TRANSLATIONS and an entry to LANGUAGES: every key must exist in 'en'."""
from __future__ import annotations

DEFAULT_LANGUAGE = "en"

# code -> native name (never translated)
LANGUAGES = {"it": "Italiano", "en": "English"}

TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # --- window / header
        "app.subtitle": "Find related domains through Certificate Transparency",
        "lang.label": "Language",
        # --- input
        "input.placeholder": "example.com or Company Name",
        "input.tooltip": "Enter a domain (example.com) or an organization name",
        "btn.scan": "Start scan",
        "btn.cancel": "Cancel",
        "opt.org": "Expand by organization",
        "opt.org.tip": "Find the certificate owner and list every domain registered to it",
        "opt.ip": "IP fallback",
        "opt.ip.tip": "If only subdomains are found, look up other sites on the same IP",
        "type.none": "Type: not set",
        "type.domain": "Type: domain",
        "type.org": "Type: organization",
        "kind.domain": "domain",
        "kind.org": "organization",
        # --- results
        "results.title": "Related domains",
        "results.count": "{n} domains",
        "results.count_filtered": "{shown} of {total} domains",
        "results.filter": "Filter results…",
        "results.hint": "Enter a domain or an organization name, then start the scan.",
        "results.none": "No useful results.",
        "btn.copy": "Copy all",
        "btn.export": "Export…",
        "btn.clear": "Clear",
        "ctx.copy": "Copy selected",
        # --- log
        "log.title": "Activity log",
        # --- status
        "status.ready": "Ready",
        "status.running": "Scanning…",
        "status.done": "Done: {n} domains in {secs} s",
        "status.cancelled": "Scan cancelled",
        "status.error": "No data received. Check your connection and try again.",
        "status.invalid": "Enter a domain or an organization name.",
        "status.copied": "{n} domains copied to the clipboard",
        # --- export
        "export.title": "Export results",
        "export.filter": "Text file (*.txt);;CSV file (*.csv)",
        "export.done": "Exported {n} domains to {path}",
        "export.fail": "Export failed: {err}",
        # --- engine log
        "log.start": "Starting scan for '{target}' ({kind}).",
        "log.query": "Querying: {url}",
        "log.retry_http": "HTTP {code}. Retrying in {wait} s… ({n}/{max})",
        "log.retry_error": "{name}. Retrying in {wait} s… ({n}/{max})",
        "log.bad_json": "Invalid server response. Retrying in {wait} s… ({n}/{max})",
        "log.http_err": "HTTP {code}.",
        "log.ct_failed": "Certificate Transparency returned no data.",
        "log.ct_count": "Certificate Transparency: {n} unique names.",
        "log.org_extracted": "Organization found in certificates: '{org}'. Expanding…",
        "log.org_tls": "Organization found in the live TLS certificate: '{org}'. Expanding…",
        "log.org_none": "No usable organization found: expansion skipped.",
        "log.only_subdomains": "Only direct subdomains found. Starting IP pivot…",
        "log.ip_fallback": "Fallback: resolving IP and reverse lookup…",
        "log.ip_resolved": "IP resolved: {ip}",
        "log.ip_found": "Reverse IP: {n} additional domains.",
        "log.cdn_ip": "IP belongs to a CDN/cloud provider. Pivot not effective.",
        "log.no_reverse": "No results from reverse IP.",
        "log.rate_limited": "Reverse IP service quota exceeded. Try again later.",
        "log.dns_error": "DNS error: {err}",
        "log.cancelled": "Scan cancelled.",
        "log.done": "Finished: {n} related domains in {secs} s.",
        "log.failed": "Unexpected error: {err}",
    },
    "it": {
        # --- window / header
        "app.subtitle": "Trova domini correlati tramite Certificate Transparency",
        "lang.label": "Lingua",
        # --- input
        "input.placeholder": "dominio.it oppure Nome Azienda",
        "input.tooltip": "Inserisci un dominio (dominio.it) o il nome di un'organizzazione",
        "btn.scan": "Avvia scansione",
        "btn.cancel": "Annulla",
        "opt.org": "Espandi per organizzazione",
        "opt.org.tip": "Trova il titolare del certificato ed elenca tutti i domini a suo nome",
        "opt.ip": "Fallback IP",
        "opt.ip.tip": "Se trova solo sottodomini, cerca altri siti sullo stesso IP",
        "type.none": "Tipo: non impostato",
        "type.domain": "Tipo: dominio",
        "type.org": "Tipo: organizzazione",
        "kind.domain": "dominio",
        "kind.org": "organizzazione",
        # --- results
        "results.title": "Domini correlati",
        "results.count": "{n} domini",
        "results.count_filtered": "{shown} di {total} domini",
        "results.filter": "Filtra risultati…",
        "results.hint": "Inserisci un dominio o il nome di un'organizzazione e avvia la scansione.",
        "results.none": "Nessun risultato utile.",
        "btn.copy": "Copia tutto",
        "btn.export": "Esporta…",
        "btn.clear": "Pulisci",
        "ctx.copy": "Copia selezione",
        # --- log
        "log.title": "Registro attività",
        # --- status
        "status.ready": "Pronto",
        "status.running": "Scansione in corso…",
        "status.done": "Completato: {n} domini in {secs} s",
        "status.cancelled": "Scansione annullata",
        "status.error": "Nessun dato ricevuto. Controlla la connessione e riprova.",
        "status.invalid": "Inserisci un dominio o il nome di un'organizzazione.",
        "status.copied": "{n} domini copiati negli appunti",
        # --- export
        "export.title": "Esporta risultati",
        "export.filter": "File di testo (*.txt);;File CSV (*.csv)",
        "export.done": "Esportati {n} domini in {path}",
        "export.fail": "Esportazione non riuscita: {err}",
        # --- engine log
        "log.start": "Avvio scansione per '{target}' ({kind}).",
        "log.query": "Interrogo: {url}",
        "log.retry_http": "HTTP {code}. Nuovo tentativo tra {wait} s… ({n}/{max})",
        "log.retry_error": "{name}. Nuovo tentativo tra {wait} s… ({n}/{max})",
        "log.bad_json": "Risposta del server non valida. Nuovo tentativo tra {wait} s… ({n}/{max})",
        "log.http_err": "HTTP {code}.",
        "log.ct_failed": "Certificate Transparency non ha restituito dati.",
        "log.ct_count": "Certificate Transparency: {n} nomi unici.",
        "log.org_extracted": "Organizzazione trovata nei certificati: '{org}'. Espansione…",
        "log.org_tls": "Organizzazione trovata nel certificato TLS attivo: '{org}'. Espansione…",
        "log.org_none": "Nessuna organizzazione utilizzabile: espansione saltata.",
        "log.only_subdomains": "Trovati solo sottodomini diretti. Avvio IP pivot…",
        "log.ip_fallback": "Fallback: risoluzione IP e reverse lookup…",
        "log.ip_resolved": "IP risolto: {ip}",
        "log.ip_found": "Reverse IP: {n} domini aggiuntivi.",
        "log.cdn_ip": "L'IP appartiene a una CDN/cloud. Pivot non efficace.",
        "log.no_reverse": "Nessun risultato dal reverse IP.",
        "log.rate_limited": "Quota del servizio reverse IP esaurita. Riprova più tardi.",
        "log.dns_error": "Errore DNS: {err}",
        "log.cancelled": "Scansione annullata.",
        "log.done": "Terminato: {n} domini correlati in {secs} s.",
        "log.failed": "Errore imprevisto: {err}",
    },
}

_current = DEFAULT_LANGUAGE


def detect_language(hint: str | None = None) -> str:
    """Map a locale name such as 'it_IT' or 'en-US' to a supported code."""
    code = (hint or "").replace("-", "_").split("_")[0].lower()
    return code if code in TRANSLATIONS else DEFAULT_LANGUAGE


def set_language(code: str) -> str:
    global _current
    _current = code if code in TRANSLATIONS else DEFAULT_LANGUAGE
    return _current


def get_language() -> str:
    return _current


def tr(key: str, **kw) -> str:
    """Translate 'key' into the active language, falling back to English."""
    text = TRANSLATIONS.get(_current, {}).get(key) or TRANSLATIONS[DEFAULT_LANGUAGE].get(key, key)
    try:
        return text.format(**kw) if kw else text
    except (KeyError, IndexError, ValueError):
        return text
