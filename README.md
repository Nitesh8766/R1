# 🛡 Malware Static Analysis Workbench

A college mini-project for a Malware Analysis subject: a web-based static
analysis tool for Windows PE (portable executable) files, built on top of a
Python/`pefile` analysis engine.

> **STATIC ANALYSIS ONLY.** This project never executes, detonates, or
> launches an analyzed file. It never runs a string or command extracted
> from a sample, and it never contacts a URL/IP/domain found inside one.
> All indicators are heuristic; a suspicious indicator is not proof that a
> file is malicious.

---

## Objective

Demonstrate the core methodology of malware **static analysis** — examining
a suspicious file's structure, imports, strings, and byte-level
characteristics without ever running it — and present the results through
a clear, explainable risk score rather than a black-box verdict.

## Features

- **PE structural analysis** — sections, entropy, RWX permissions, packer
  section-name signatures, entry-point sanity, zero timestamps
- **Import analysis** — ~50 commonly abused Windows APIs categorized into
  process injection, persistence, anti-debug, keylogging, network, privilege
  escalation, and more
- **String analysis** — ASCII *and* UTF-16LE (wide) string extraction, with
  pattern matching for shell/PowerShell references, ransom-note language,
  shadow-copy deletion, registry Run keys, VM-detection strings, etc.
- **Overlay detection** — flags high-entropy data appended past the last
  section (a common payload-hiding technique)
- **Authenticode check** — flags unsigned binaries (weak signal, low weight)
- **TLS callback detection** — flags code that runs before the declared
  entry point (an anti-debug technique)
- **Static IOC extraction** — URLs, IPv4 addresses, domains, emails, Windows
  paths, registry paths, `.onion` addresses, hash-like strings — extracted
  and *displayed only*, never contacted
- **MITRE ATT&CK mapping** — conservative, evidence-linked mapping from
  detected indicators to technique IDs
- **Weighted risk scoring** — raw score → normalized score (capped at 100)
  → LOW / MEDIUM / HIGH verdict, with configurable thresholds
- **Web dashboard** — upload/drag-drop, risk gauge, category breakdown,
  searchable/filterable findings, PE section table, entropy bars, import
  groups, paginated string explorer, IOC panel, MITRE table
- **Analysis history** — SQLite-backed, click a past analysis to reload it
- **HTML report generation** — self-contained, downloadable report per
  analysis
- **CLI** — the underlying engine also runs standalone: `python malware.py <file> [--json]`

## Architecture

```
Upload sample
     │
     ▼
Web Dashboard (frontend/: HTML + CSS + vanilla JS)
     │  fetch()
     ▼
API Backend (backend/api.py — Flask)
     │  saves upload to a temp file, deletes it after analysis
     ▼
Analysis Engine (backend/malware.py — uses pefile)
     │  structured dict (see "Output shape" below)
     ▼
SQLite History (backend/database.py)
     │
     ▼
Dashboard render + Report generation (backend/report.py)
```

Stack: **Python, Flask, HTML/CSS/vanilla JS, `pefile`, SQLite.** No
React/Vite/Node build step — the project runs directly on a phone under
Termux with just `pip install` and `python api.py`.

## Project structure

```
malware-analyzer/
├── backend/
│   ├── malware.py       # analysis engine (CLI + importable)
│   ├── api.py            # Flask routes
│   ├── schemas.py        # Finding schema, severities, MITRE map, thresholds
│   ├── database.py       # SQLite history
│   └── report.py          # standalone HTML report generator
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── samples/
│   └── demo.exe           # benign, hand-crafted test PE (see note below)
├── reports/                # generated HTML reports land here
├── uploads/                # transient upload staging (files deleted after analysis)
├── requirements.txt
└── README.md
```

## Installation

```bash
cd malware-analyzer
pip install -r requirements.txt --break-system-packages   # Termux/Android needs the flag; drop it elsewhere if it errors
```

## Usage

### Web dashboard

```bash
cd backend
python api.py
```

Then open `http://127.0.0.1:5000` in a browser (works fine in the phone's
own browser under Termux, since the server binds to `0.0.0.0`).

The server also tries to open the dashboard for you automatically on
startup — in Termux it uses `termux-open-url` if the Termux:API
app/package is installed, and falls back to the standard `webbrowser`
module elsewhere. If auto-open doesn't fire in your environment, just
open the printed URL manually.

### CLI

```bash
cd backend
python malware.py ../samples/demo.exe
python malware.py ../samples/demo.exe --json
python malware.py ../samples --recursive
```

## Static-analysis methodology

The engine never runs the target file. Instead it:

1. Hashes it (SHA-256) for identification.
2. Parses the PE structure with `pefile` — sections, entry point, TLS
   directory, security directory, import table.
3. Computes Shannon entropy per section (and for overlay data / whole file
   if it isn't a valid PE) to flag likely packing/encryption.
4. Cross-references imported function names against a table of commonly
   abused Windows APIs.
5. Extracts printable strings (ASCII and UTF-16LE) and matches them against
   regex patterns associated with known malicious behaviors.
6. Extracts static indicators of compromise via regex (never resolved or
   contacted).
7. Every match above becomes a **finding**: a category, severity, score,
   and a plain-language explanation of *why* it's relevant.

## Risk-scoring methodology

Every finding carries an integer weight reflecting how strong a signal it
is in isolation (e.g. `CreateRemoteThread` = 10, a bare URL string = 2).
Weights sum to a **raw score**. The raw score is capped at 100 for display
as a **normalized score**, and mapped to a verdict:

| Raw score | Verdict |
|-----------|---------|
| 0–14      | 🟢 LOW |
| 15–34     | 🟡 MEDIUM |
| 35+       | 🔴 HIGH |

Thresholds live in `backend/schemas.py` (`RISK_THRESHOLDS`) and are
intentionally easy to point to and change.

**This is a heuristic classification, not a malware determination.** The
report and dashboard both say so explicitly: *"HIGH RISK based on detected
static indicators,"* never *"100% malware."*

## Limitations

- Static analysis only observes artifacts present in the file on disk. It
  cannot see runtime-only behavior, and heavily obfuscated or
  dynamically-resolved malware can evade many of these specific checks.
- Legitimate software can and does use the same APIs, strings, and even
  packers flagged here (installers, DRM, anti-cheat, etc.) — false
  positives are expected and by design the tool explains *why* something
  was flagged rather than asserting certainty.
- The suspicious-API and string-pattern tables are illustrative for a
  mini-project, not an exhaustive industry ruleset.
- MITRE ATT&CK mappings are shown only where a specific static indicator
  directly supports them — this is not a full behavioral analysis.

## Testing

The included `samples/demo.exe` is a hand-crafted, functionally inert PE
file (its only "code" is `xor eax,eax; ret`) built specifically to exercise
every heuristic in the engine: an RWX section, a packer-style section name
with high-entropy data, several suspicious imports across multiple DLLs,
and several suspicious string patterns. **Its score is never hardcoded
anywhere in the codebase** — running it through the engine is a genuine
end-to-end test of the scoring pipeline, not a canned demo.

Also test:
- A benign/clean PE (e.g. a small legitimate `.exe`) — should score LOW.
- A non-PE file renamed to `.exe` — exercises the fallback entropy/string
  path.
- An empty file — handled explicitly (`"file is empty"` error, no crash).
- A truncated/corrupted PE — the engine wraps per-section parsing in
  `try/except` so a malformed section degrades gracefully instead of
  crashing the whole analysis.

## Viva prep — likely questions

**What is malware static analysis?**
Analyzing a suspicious file's structure and content without executing it.

**What does the project analyze?**
PE structure, imports, strings, entropy, sections, suspicious patterns, and
static IOCs.

**How is the score calculated?**
Every detected indicator carries a weight; weights sum to a raw score,
which is capped and mapped to LOW/MEDIUM/HIGH against configurable
thresholds.

**Why can false positives happen?**
Legitimate applications can use APIs like `CreateRemoteThread`, PowerShell,
networking APIs, or registry operations for entirely benign reasons — the
tool flags *presence*, not intent.

**Why isn't the verdict definitive?**
Static analysis only observes what's on disk; it can't see obfuscated logic
that only resolves at runtime, and it can't observe actual behavior the way
a sandbox/dynamic analysis would.

## Future improvements

- PDF export of the report (currently HTML only)
- YARA rule integration
- A curated, larger suspicious-API/string ruleset
- Authenticode signature *validation* (currently presence-only)
- Optional sandboxed dynamic analysis as a separate, clearly-labeled module
