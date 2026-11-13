# OSINT Tracker

[English](README.md) | **Italiano**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Version](https://img.shields.io/badge/version-1.5.0-green)
![Piattaforma](https://img.shields.io/badge/piattaforma-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

**Trova domini correlati tramite Certificate Transparency.**
Uno strumento desktop multipiattaforma che sfrutta `crt.sh` e il reverse-IP lookup per ricostruire l'intera impronta di domini di un obiettivo.

---

## Panoramica

OSINT Tracker riceve un dominio o il nome di un'organizzazione e restituisce l'insieme dei domini ad essa associati, usando tre canali di ricerca complementari:

1. **Certificate Transparency** »  interroga `crt.sh` per ogni certificato emesso per l'obiettivo (o per il nome dell'organizzazione inserito).
2. **Espansione per organizzazione** »  estrae il campo `O=` (organizzazione) dal certificato, ripiegando su un handshake TLS in tempo reale, quindi interroga di nuovo `crt.sh` con quel nome per recuperare tutti i domini "fratelli".
3. **Pivot reverse-IP** »  quando i primi due passaggi restituiscono solo l'obiettivo e i suoi sottodomini diretti, risolve l'IP e interroga `api.hackertarget.com/reverseiplookup` per trovare altri siti ospitati sullo stesso server.

Il motore è indipendente da Qt, pensato per essere testabile offline, e comunica l'avanzamento tramite una callback strutturata `emit(level, key, **kwargs)` che la GUI traduce al volo.

---

## Funzionalità

- **Due modalità di input** »  dominio (`example.com`) oppure nome di un'organizzazione (`Acme Corp`). Anche gli URL sono accettati e vengono ridotti al solo hostname.
- **Estrazione live dell'organizzazione via TLS** »  legge il vero `organizationName` dal certificato servito sulla porta 443, perché l'output JSON di `crt.sh` non sempre include il subject del certificato.
- **Filtro anti-CDN** »  ignora il rumore di AWS / Cloudflare / Akamai / Fastly / Azure / Google Cloud / Oracle Cloud, sia a livello di organizzazione sia di IP.
- **Rete resiliente** »  nuovi tentativi automatici con attesa progressiva su `429`, `502`, `503`, `504`, errori di rete e risposte JSON malformate.
- **Scansioni annullabili** »  ogni chiamata di rete e ogni attesa è interrompibile tramite un `threading.Event`.
- **Interfaccia scura** »  stylesheet PySide6 personalizzato, registro attività a spaziatura fissa, lista risultati filtrabile, menu contestuale, scorciatoie da tastiera.
- **Bilingue** »  italiano / inglese, rilevato dalla lingua di sistema e memorizzato tramite `QSettings`.
- **Esportazione** »  testo semplice (`.txt`, un dominio per riga) o CSV (`.csv`, con intestazione `domain`).
- **Nessuna risorsa esterna** »  l'icona dell'applicazione è generata a runtime come SVG (XML); non vengono distribuiti file immagine.

---

## Requisiti

- **Python 3.10+**
- Dipendenze:
  - [`PySide6`](https://doc.qt.io/qtforpython/) »  binding Qt 6 (GUI e rendering SVG)
  - [`requests`](https://requests.readthedocs.io/) »  client HTTP

Nessun pacchetto di sistema, nessun file di Qt Designer, nessuna risorsa binaria.

> **Nota Linux:** su alcune distribuzioni (ad es. Ubuntu/Debian) Qt 6 può non avviarsi con un errore relativo al plugin di piattaforma `xcb`. Di solito si risolve installando `libxcb-cursor0`:
> `sudo apt install libxcb-cursor0`

---

## Installazione

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

## Utilizzo

```bash
python main.py
```

1. Inserisci un dominio (`example.com`) o il nome di un'organizzazione nel campo di input.
2. Imposta le opzioni:
   - **Espandi per organizzazione** »  trova il titolare del certificato ed elenca tutti i domini a suo nome.
   - **Fallback IP** »  se vengono trovati solo sottodomini diretti, effettua il pivot sull'IP risolto.
3. Premi **Invio** o clicca su **Avvia scansione**.
4. I risultati compaiono nella lista; puoi filtrarli, copiarli o esportarli.

### Scorciatoie da tastiera

| Scorciatoia | Azione |
|-------------|--------|
| `Invio` | Avvia la scansione |
| `Esc` | Annulla la scansione |
| `Ctrl+L` | Sposta il focus sull'input |
| `Ctrl+F` | Sposta il focus sul filtro |
| `Ctrl+E` | Esporta i risultati |
| `Ctrl+C` (nella lista) | Copia i domini selezionati |

---

## Architettura

```
osint-tracker/
├── main.py            # GUI PySide6, tema, generazione icona, thread di lavoro
├── core.py            # Motore senza Qt: crt.sh, estrazione org via TLS, reverse-IP
├── i18n.py            # Tabella stringhe bilingue (IT / EN)
├── requirements.txt
├── LICENSE
├── README.md
└── README.it.md
```

### `core.py` »  il motore

- `run_scan(target, expand_org, ip_fallback, cancel, emit)` → `ScanResult`
- `get_domains_from_ct(...)` »  interroga `crt.sh`, con espansione opzionale per organizzazione.
- `fetch_org_via_tls(host, cancel)` »  singolo handshake TLS per leggere l'organizzazione.
- `get_domains_from_ip(...)` »  risolve l'IP, interroga HackerTarget, filtra gli indicatori CDN.
- `retry_request(...)` »  logica di retry condivisa, con attesa progressiva e supporto all'annullamento.
- Il motore non stampa e non traduce mai: la presentazione è compito della GUI.

### `main.py` »  la GUI

- `ScanWorker` »  `QObject` che esegue `core.run_scan` in un thread daemon e comunica tramite segnali Qt.
- `MainWindow` »  costruisce l'interfaccia, collega i segnali, gestisce scorciatoie e stato.
- `build_icon_svg()` »  genera a runtime l'icona radar come XML; viene resa a 7 dimensioni (16 → 256 px) tramite `QSvgRenderer`.
- `build_stylesheet()` »  inserisce la palette colori nel template QSS.

### `i18n.py` »  traduzioni

- Dizionario `TRANSLATIONS` con due blocchi linguistici (`en`, `it`); ogni chiave deve esistere in `en`.
- `tr(key, **kw)` »  formatta la stringa, ripiega sull'inglese, non solleva mai eccezioni.
- `detect_language(locale)` »  associa `it_IT`, `en-US`, ecc. a un codice supportato.

Per aggiungere una lingua, inserisci un nuovo blocco in `TRANSLATIONS` e una voce in `LANGUAGES` dentro `i18n.py`.

---

## Fonti dati

| Fonte | Endpoint | Scopo |
|-------|----------|-------|
| crt.sh | `https://crt.sh/?q=...&output=json` | Log di Certificate Transparency |
| HackerTarget | `https://api.hackertarget.com/reverseiplookup/?q=...` | Reverse-IP lookup |
| TLS live | porta 443 tramite la libreria standard `ssl` | Estrazione dell'organizzazione |

Non servono chiavi API. Gli errori temporanei vengono ritentati automaticamente; la quota gratuita di HackerTarget è limitata e, quando si esaurisce, lo strumento lo segnala nel registro attività e prosegue senza i risultati reverse-IP.

---

## Privacy e uso responsabile

- L'obiettivo che inserisci viene inviato a servizi di terze parti (`crt.sh` e, se usi il fallback IP, HackerTarget).
- Il passaggio **Espandi per organizzazione** apre una connessione TLS diretta verso l'obiettivo sulla porta 443, e il **Fallback IP** ne risolve il nome DNS. Sono le uniche richieste che raggiungono direttamente l'obiettivo.
- Usa questo strumento solo su domini e organizzazioni di tua proprietà o che sei autorizzato a investigare. Sei responsabile del rispetto delle leggi e dei termini di servizio applicabili.

---

## Crediti

Creato da **Raffaele Catapano** »  [github.com/MrGodLink](https://github.com/MrGodLink)

Se riutilizzi, modifichi o ridistribuisci questo progetto, mantieni l'avviso di copyright e cita l'autore originale, come richiesto dalla licenza MIT.

Segnalazioni di bug e idee sono benvenute nelle [issue](https://github.com/MrGodLink/osint-tracker/issues).

## Licenza

Il codice sorgente è rilasciato sotto licenza MIT »  vedi [LICENSE](LICENSE).

OSINT Tracker dipende da [PySide6](https://doc.qt.io/qtforpython/), distribuito con licenza LGPLv3 (o con licenza commerciale Qt). Viene installato separatamente (tramite `pip` o la tua distribuzione). Se distribuisci un eseguibile incluso in un bundle (ad esempio creato con PyInstaller), devi rispettare anche i termini LGPL di PySide6 e Qt.
