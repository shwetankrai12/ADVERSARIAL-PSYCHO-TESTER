# Tier-2 Agents — Substrate-Level Failure Classes

Ten agents attacking the **layers the application depends on but does not control**: Unicode normalizers, regex engines, document parsers, font shapers, the clipboard contract, audio hardware, floating-point rounding, timezone databases, AI models, CSS engines. These survive code review because the code *looks* correct — the failure lives one layer below, in a library nobody on the team owns.

**Contents:** 1 Normalization Shapeshifter · 2 ReDoS Whisperer · 3 Infinite Loop Poisoner · 4 Font Bomber · 5 Clipboard Trojan · 6 Silent Sensor · 7 Rounding Drainer · 8 Timezone Ghost · 9 AI Gaslighter · 10 CSS Heap Corruptor

---

## Agent T2-1 — The Normalization Shapeshifter

**Precedent.** CVE-2026-100674 (stoatchat): username allowlists and length limits bypassed via Unicode normalization quirks. An Auth.js vulnerability validated an email **before** NFKC normalization — an address containing `U+FF20` (FULLWIDTH COMMERCIAL AT `＠`) isn't an ASCII `@` at validation time, but canonicalizes *to* one downstream, so the mail library saw two separators. WildFly Elytron NFKC-normalized passwords, collapsing fullwidth characters toward ASCII and making guessing easier.

**Mechanism.** Validation and consumption disagree about *what the string is* because a normalization pass sits between them. The submitted form is legal and displayable; the canonical form is a different string.

**Applies to.** Usernames, emails, passwords, filenames, group/channel names — anywhere an allowlist, uniqueness check, or length check runs before a normalizing consumer (mail library, filesystem, DB collation, search index).

**Payloads.**
```bash
python scripts/payloads.py get normalization
```
Fullwidth `＠ Ａ ａ` (U+FF20 etc.), mathematical alphanumerics (U+1D400 region — bold 𝐀), NFKC-compatibility characters (① ™ ㌀), ligatures `ﬁ`, combining sequences that compose (`e` + U+0301 → é), fullwidth-digit account names, halfwidth kana.

**Playbook.**
1. Register/submit with the fullwidth form (`ＮＵＬＬ`, `admin＠example.ｃom`). Note validation's verdict.
2. Then attempt the *same logical operation* with the ASCII-equivalent form (`NULL`, `admin@example.com`). If the first was accepted where the second would be blocked (allowlist bypass), or the two collide on one account/record (uniqueness checked on one form, stored as the other) — that's the finding.
3. Probe length checks: fullwidth characters often count as 1 before normalization but the normalized form is longer/shorter — submit ` maxlength`-sized fullwidth strings, round-trip, and compare.
4. Password surfaces: if passwords are normalized (WildFly class), typing a fullwidth `Ａ` may authenticate against an ASCII `A` — test both directions.
5. Code track: `rg "normalize|NFKC|NFC\(|toLocaleLowerCase|toLowerCase"` — the danger sign is normalization *after* validation, or normalization applied inconsistently (login normalizes, registration doesn't).

**Observe at.** The equivalence decisions: what the system treats as *the same string* at validation vs storage vs lookup vs auth.

**Invariant.** One canonicalization point, applied *before* every check that depends on it: `validate(normalize(x))`, never `normalize(validate(x))`. Two visually distinct strings that normalize equal must be detected as collisions.

**Failure signatures → severity.** Allowlist bypass via fullwidth → **P1**. Account collision / takeover of an ASCII-named account via normalized form → **P0**. Password normalization weakening → **P1**. Length-check bypass → **P2**. Consistent canonicalization → **P4**.

**Fix guidance.** Normalize once, early (NFC for identity strings; NFKC only with a documented reason), *then* validate, *then* store the normalized form; enforce uniqueness on the canonical form; never normalize passwords.

---

## Agent T2-2 — The ReDoS Whisperer

**Precedent.** Cloudflare 2019: one vulnerable regex in the WAF → **27-minute global outage**. Stack Overflow 2016: a malformed regex → **34 minutes down**. Mechanism: catastrophic backtracking — patterns like `(a+)+`, `(.*)*`, `(a|a)*` on adversarial input force exponential path exploration.

**Mechanism.** A regex with nested/overlapping quantifiers meets a structurally-valid-but-pathological input; the engine's CPU cost explodes exponentially with input length.

**Applies to.** Every field validated by regex: emails, URLs, phone numbers, postal codes, usernames, search inputs, header-parsing middleware, template/BBCode parsers.

**Payloads.**
```bash
python scripts/payloads.py get redos
```
`a`×30 + `!`, `a@` + `a`×30 + `.com` (email shapes), `0.` + digit runs with separators, long runs of `%20`-style optional segments, nested-dashes strings, `a`×32 + `b` for `(a+)+$` shapes, 20-term dotted strings for `(\w+)*` URL validators, plus a length-ladder (10/20/40/80 chars) to *measure* the exponent.

**Playbook.**
1. **Map the validated fields first.** Send one input with a clearly invalid character to every field; a 400 / "invalid X" response is your map of where validators — and their regexes — live. Unvalidated fields cannot ReDoS anything, so laddering them proves nothing (probing an unvalidated field and reporting "flat timing, no ReDoS" is the classic false negative this agent exists to avoid).
2. Run the corpus against each *validated* field. Every ladder input must be a **failing match**: valid-charset characters plus one invalid terminator (`a`×30 + `!`). Valid inputs that match quickly prove nothing — backtracking cost only explodes when the engine must *fail*. Measure response time per rung: **exponential growth across rungs is the proof** (linear growth is just slow; ~4× time per +2 chars is the smoking gun).
3. In a browser: also watch the *client-side* regexes (login forms, signup validators) — paste the payload into the field and see if the tab hangs (client ReDoS is the same bug, different victim).
4. Keep each probe under a few seconds of server pain — the length ladder is the responsible way to demonstrate the exponent without an outage. If a rung already costs seconds, stop there; the extrapolation *is* the finding.
5. Code track: `rg "\(.*[+*].*\)[+*]|\(.*\|.*\)[+*]|\(\.\*\)\+|\(\.+\)\*"` — nested quantifiers, alternation-with-self inside a quantified group; also `\w*\w*` adjacency pairs; flags: Python `re` in a request path, JS `new RegExp(userInput)` (that last one is *user-supplied pattern*, worse: instant ReDoS of your own choosing).

**Observe at.** Response-time scaling with input length — the curve, not one slow request.

**Invariant.** Validation cost is bounded ~linearly in input length, for *all* inputs.

**Failure signatures → severity.** Exponential curve confirmed server-side → **P1** (one real user's stray paste can pin a worker). Client-side hang → **P2** (tab frozen, user blames your app). Linear-but-slow on huge inputs → **P3**. Linear + bounded input → **P4**.

**Fix guidance.** Rewrite the vulnerable patterns (possessive/atomic groups where supported, unroll loops, anchor early, cap input length *before* regex); move expensive validation off the hot path; add regex linting to CI (safe-regex /regexpert-class tools); never `new RegExp(user_input)` without escaping.

---

## Agent T2-3 — The Infinite Loop Poisoner

**Precedent.** CVE-2026-42310 (Pillow `PdfParser`): following trailer `/Prev` pointers **without cycle detection** — a trailer whose Prev points at itself (or forms a longer cycle) sent the parser into an infinite loop, 100% CPU, service hung indefinitely. Wide version range affected; fix = cycle detection.

**Mechanism.** A syntactically-valid but *self-referential* structure drives a pointer/graph-following loop with no cycle guard and no termination.

**Applies to.** PDF/JSON/XML/YAML parsers, archive unpackers, link/graph processors, pagination followers, anything that chases embedded references (JSON `$ref`, YAML anchors/aliases, SVG `use` elements, symlink-holding zips).

**Payloads.**
```bash
python scripts/payloads.py make cyclic-pdf --out loop.pdf
```
Plus buildables documented in the payload script: self-referential JSON (`{"$ref": "#"}` or `{"a": {"$ref": "#/a"}}`), YAML billion-laughs-style alias expansion (if the surface accepts YAML), recursive ZIP (a zip containing a symlink loop or nested self-extraction), SVG with `<use xlink:href="#x">` cycles.

**Playbook.**
1. Upload the cyclic PDF to every PDF-processing surface. Watch for: request never completing (use a client timeout of 30–60 s so *you* terminate, then note the server worker still pinned — if you can observe process CPU from the shell on an owned box, do), CPU at 100% with no crash, worker pool exhaustion on subsequent uploads.
2. Submit self-referential JSON to any API accepting JSON-pointer/`$ref` semantics; submit cyclic YAML if any config-import surface exists.
3. The health-check paradox: if the app's liveness probe only checks process-alive, note that the hung worker is invisible to orchestration — that's part of the finding, not an excuse.
4. Code track: `rg "while .*next|while .*prev|\.get\(['\"]prev|follow.*link|unpack|extractall"` — every loop following pointers needs a seen-set or depth cap; `tarfile.extractall` without filter; recursive descent without depth limit.

**Observe at.** Termination itself: does processing *finish* (rejecting the file counts as finishing)? Pin one probe at a time and confirm the worker recovers.

**Invariant.** Every parser terminates on every input: bounded iterations via cycle detection or depth/size budgets.

**Failure signatures → severity.** Server hang, worker pinned → **P1**. Pool exhaustion by a few uploads → **P0** (availability). Client-side parse hang in JS → **P2**. Clean rejection/timeout with worker freed → **P4**.

**Fix guidance.** Cycle detection (seen-set) or hard depth/iteration caps in every reference-following loop; global processing timeouts *with worker cancellation*, not just client timeouts; size/amplification budgets for alias-expanding formats (YAML anchors, XML entities); keep library bomb protections enabled.

---

## Agent T2-4 — The Font Bomber

**Precedent.** CVE-2026-110605 (libschrift): crafted TrueType with `unitsPerEm = 0` → divide-by-zero in `draw_line()`. CVE-2026-95512 (FreeType CID loader): crafted font triggered **repeated allocation + decryption of subroutine data** across font dictionaries → memory/CPU exhaustion. CVE-2026-113680 (HarfBuzz): NULL-pointer deref via crafted WebAssembly shaper in an embedded font.

**Mechanism.** Fonts are parsed by C/C++ shapers assuming trusted metrics; user-supplied fonts with zeroed/cyclic/pathological structures crash or exhaust the text-rendering pipeline — far from the upload form that accepted them.

**Applies to.** Anywhere users supply or select fonts: profile/themes customization, document upload (embedded fonts in DOCX/PDF), design tools, brand-kit uploads, `@font-face` with user-controlled URLs in CSS themes.

**Payloads.**
```bash
python scripts/payloads.py make bomb-font --out bad.ttf   # unitsPerEm=0 skeleton TrueType
```
Plus (documented in the script): take any system TTF, hex-patch `unitsPerEm` to 0 / tiny / huge values, zero the `numGlyphs` or metrics fields, truncate the glyf table — a 20-byte patch turns a valid font into a crash probe.

**Playbook.**
1. Identify the font surface. If there's *no* font-upload/theming surface, mark `skipped` — this agent is common in design/editor/product-customization apps only.
2. Upload the crafted font; then trigger a **render** that uses it (preview, theme application, document render). The crash happens at render time, not upload time — that delay is the class signature.
3. Watch the rendering process (server-side converters, browser tab) for crashes, OOM, CPU pinning.
4. If fonts arrive via `@font-face` URLs in user CSS, test the URL-fetch path: does the server fetch and parse arbitrary remote fonts? (SSRF + font parser in one.)
5. Code track: `rg "font|ttf|otf|woff"` in upload handling; embedded-font extraction from PDFs/DOCX (mupdf, FreeType usage — pin library versions against known CVEs); server-side rendering (Pillow+FreeType, headless Chrome) that touches user fonts.

**Observe at.** The rendering process — crash-at-render is the signature; a successful upload proves nothing.

**Invariant.** Font metrics are validated before shaping; untrusted fonts render in a sandboxed, resource-capped path; parser libraries are current against known font CVEs.

**Failure signatures → severity.** Renderer crash / divide-by-zero → **P1**. Memory exhaustion via repeated subroutine processing → **P1**. RCE-adjacent (memory corruption class) → **P0** (report conservatively: "crash on crafted input in a C parser" is a P1 unless code-exec is proven; note the CVE precedent). No font surface → `skipped`.

**Fix guidance.** Validate font structure before use (fontTools can parse and check `unitsPerEm`, table sanity); render untrusted fonts in isolated, resource-limited workers; keep FreeType/HarfBuzz/Chromium current; proxy-fetch `@font-face` URLs from an allowlist, never the raw user URL.

---

## Agent T2-5 — The Clipboard Trojan

**Precedent.** CVE-2026-86712 (SiYuan): the Electron app trusted the attacker-writable `text/siyuan` clipboard MIME type and skipped sanitization in its paste handler — a malicious webpage wrote the clipboard, and pasting into SiYuan executed scripts **with full Node.js access via the Electron main process**. Chromium-on-Linux: a page could silently overwrite the X11 PRIMARY selection; middle-clicking the omnibox navigated to the poisoned clipboard content.

**Mechanism.** The clipboard is treated as a trusted channel because *the user* initiates the paste — but the *content* was written by any page the user visited. The failure fires after the paste, in a different process, often with elevated privileges.

**Applies to.** Rich-text editors, note apps, code editors, Electron/desktop shells of the web app, paste handlers that switch on MIME type, "paste from Word/Excel" import features.

**Payloads.** Constructed clipboard payloads (the script documents them): HTML-with-script under a custom MIME flavor, `text/html` containing `<img src=x onerror=...>`, event-forged paste objects (`clipboardData.setData('text/html', payload)` dispatched to the editor), oversized paste (10 MB of styled spans — a sibling resource probe).

**Playbook.**
1. This agent needs a real browser (or the desktop shell). With agent-browser: open the app's editor, dispatch a synthetic paste event carrying the crafted `text/html` payload (`page.evaluate`), and check whether script executes / Node bridges are reachable in Electron contexts.
2. In plain web apps: paste HTML into the rich-text editor and inspect the resulting DOM — `<img onerror>`, `<iframe>`, `<svg onload>` surviving sanitization is the web-tier version.
3. Test the MIME-trust pattern: does any paste handler switch on a custom MIME type and skip the sanitizer for it? (The SiYuan shape — look for `clipboardData.getData('text/<anything-custom>')` paths.)
4. Code track: `rg "paste|clipboardData|onPaste"` — sanitize *after* MIME dispatch, not before; `rg "webPreferences" ` in Electron configs — `nodeIntegration: true` + paste handlers = the full CVE shape.

**Observe at.** The resulting DOM / executed code — the paste "succeeding" is the vulnerability, not a failure.

**Invariant.** Clipboard content is untrusted input regardless of user gesture: every paste path runs the same sanitizer; custom MIME flavors get no exemption; Electron privileged bridges are unreachable from pasted content.

**Failure signatures → severity.** Script execution reaching Node/main process → **P0**. Script execution in web context → **P1** (stored-XSS-adjacent via paste). HTML structure surviving unsanitized → **P1/P2** by exploitability. Clean sanitization on all flavors → **P4**.

**Fix guidance.** Sanitize at the single point *after* all clipboard flavors are read; never branch trust on MIME flavor; in Electron: `nodeIntegration: false`, `contextIsolation: true`, no privileged IPC from renderer-pasted content; strip event handlers and external-resource loads from pasted HTML.

---

## Agent T2-6 — The Silent Sensor

**Precedent.** AliExpress was found running **silent WebAudio fingerprinting** on its homepage: two audio-processing graphs, a known signal in, device-specific result measured, volume set to zero. Side effect: Bluetooth headphones stopped switching cleanly between devices because the browser kept an inaudible audio stream open. The fingerprint exploited tiny hardware/driver differences — invisible to the user, persistent enough to identify the machine.

**Mechanism.** The app commandeers an audio device without a user gesture and keeps the context alive — a *physical-hardware* side effect and a privacy leak, not a crash.

**Applies to.** Pages that create `AudioContext` without interaction: fingerprinting scripts (first- or third-party), video players that preload audio contexts, notification-sound systems, voice-input features.

**Payloads.** None — this agent *observes* rather than injects: audio-context lifetime, gesture-gating, device-routing changes.

**Playbook.**
1. Needs a real browser. Load each page type (home, video, chat, settings) and inspect: `new AudioContext()` / `AudioContext` state at load, before any click. Check via agent-browser's JS evaluation.
2. Look for the fingerprint shape: oscillator → analyser/dynamics compressor → readback, with gain muted to 0 — `OfflineAudioContext` with an exact-sum buffer is the classic pattern (`rg "OfflineAudioContext|createOscillator|getChannelData|SumBuffer|fingerprint"` in the page scripts / repo).
3. Test the gesture gate: does audio state go `running` without a click? (Autoplay policy bypasses — e.g. via `navigator.mediaDevices` triggers — count.)
4. If any audio context stays alive after navigation/timeout, note the hardware-capture duration — that's the Bluetooth-switching side effect the AliExpress users hit.
5. For the report: distinguish *your app's legitimate* audio (video player, sounds) from *silent* contexts with no audible purpose — the latter is the finding.

**Observe at.** Audio-device state over page lifetime — a dimension most audits never instrument at all.

**Invariant.** Audio contexts are created on user gesture, used audibly, and closed when idle; no silent always-on device capture.

**Failure signatures → severity.** Silent ungated fingerprinting context → **P1** (privacy violation — regulatory exposure under GDPR/DPDP-class rules). Always-on context disrupting device switching → **P2** (physical-world UX harm). Gated, audible, closed → **P4**.

**Fix guidance.** Create AudioContext lazily on gesture; `close()` idle contexts; audit third-party scripts for fingerprinting shapes; if fingerprinting is a product requirement, disclose it and gate it.

---

## Agent T2-7 — The Rounding Drainer

**Precedent.** Balancer V2, November 2025: **$94–128M drained** via rounding asymmetry between `mulDown`/`mulUp` across batch swaps. Pyth data network: a contributor submitted a float where an integer was expected; the software **silently converted to zero** instead of erroring — Bitcoin's price "crashed 90%" on the feed. Vancouver Stock Exchange: `floor()` instead of `round()` lost fractions of cents per trade — the index lost ~50% of its value over 22 months of silent accumulation.

**Mechanism.** Rounding/precision asymmetries are invisible per-operation and catastrophic in aggregate: sequences of legitimate operations whose accumulated error becomes extractable value or compounding drift.

**Applies to.** Anything arithmetic on money, points, credits, quantities, exchange rates, percentages: wallets, carts, tax/discount calculators, reward programs, currency conversion, inventory fractions, staking/interest accrual.

**Payloads.** Chosen *values*, not strings: amounts just below/above the smallest unit boundary (e.g. `0.005`, `0.015`, `0.025` — the tie-breaking decimals), float-representable-but-inexact values (`0.1 + 0.2` class), smallest-unit amounts (1 cent / 1 satoshi / 1 point), amounts that stress `floor` vs `ceil` direction on conversion, and *sequences*: A→B→A currency round-trips repeated 100×.

**Playbook.**
1. Pick the app's smallest money unit. Deposit/convert/withdraw amounts that land exactly on rounding boundaries; check the ledger each step: does the invariant `sum(accounts) == total_supply` hold after each operation?
2. **Round-trip drift test**: convert 100.00 → other currency → back, 100 times. Measure final vs initial. Any systematic drift > accumulated fee model = finding (direction of the drift tells you who can farm it).
3. Order-of-operations: apply discount + tax + fee in the app's order on a boundary amount; compute the same in the "correct" order per the published policy; disagreement = finding.
4. Look for the Pyth shape: float-typed fields silently coerced where integers are expected (code track: `rg "float\(|parseFloat|Number\(" ` on money paths; JSON money as float instead of integer-cents/string-decimal).
5. Balancer shape: if the app pools anything (liquidity, ad inventory, shared credits), probe whether swap-out rounds *up* and swap-in rounds *down* — the extractable direction.

**Observe at.** The ledger invariant across sequences, and drift sign/direction over repetition — one operation proves nothing, which is exactly why this class survives unit tests.

**Invariant.** `total_supply == Σ balances` after every operation (conservation); rounding direction is uniform or audited; precision representation is exact (integer minor units or decimal strings, never binary floats for money).

**Failure signatures → severity.** Extractable rounding asymmetry (users can farm value) → **P0** (the Balancer class). Silent float→zero coercion on a live path → **P0** (the Pyth class). Conservation violation without extraction path → **P1**. Slow cosmetic drift in display only → **P3**. Exact arithmetic + conserved ledger → **P4**.

**Fix guidance.** Integer minor units (or decimal strings) end-to-end; one rounding policy with named direction per operation, documented; property-based tests asserting conservation over random operation sequences; reject (never coerce) type mismatches on money inputs; audit any pooling path for direction-of-rounding asymmetry.

---

## Agent T2-8 — The Timezone Ghost

**Precedent.** Amadeus On-Demand Flight Status API returned `+05:00` for Indian airports (correct: **`+05:30`**) — a silent 30-minute error in departures/arrivals. Paraguay's timezone-database lag made **all** flights to/from Paraguay display wrong durations until the tzdata update shipped. Airlines computing in UTC while selling in local time made "correct" times wrong across DST.

**Mechanism.** The same instant, represented in two systems/APIs/columns that disagree about the offset — invisible until a specific route, locale, or DST window manifests it.

**Applies to.** Booking/scheduling across zones, calendar integrations, APIs that emit timestamps with offsets, databases storing local times, itinerary math, any feature with "duration" or "local time" for a global user base.

**Payloads.**
```bash
python scripts/payloads.py get timezone-boundaries
```
Half-hour and 45-minute zones (`Asia/Kolkata +05:30`, `Asia/Kathmandu +05:45`, `Australia/Eucla +08:45`, `Australia/Lord_Howe` — 30-min DST), zone-pairs that differ by :30 (Kolkata→Colombo), DST-transition instants, date-line crossings, and the same wall-clock time submitted under two zones.

**Playbook.**
1. Book/schedule the *same logical event* through every entry point (UI form, API, calendar sync, email confirmation). Compare the resulting instants pairwise — UI vs DB vs API vs email. Any pair disagreeing = a Ghost.
2. Probe half-hour zones explicitly: enter `14:00 Kolkata` and see whether anything downstream treats it as `14:00 +05:00` or `08:30 UTC` (the Amadeus error shape).
3. DST window: schedule inside the spring-forward gap (a local time that *does not exist*) and the fall-back overlap (a local time that occurs *twice*) — the app must define behavior; silently guessing is a finding.
4. Cross-render: view a Kolkata-created event from a New York session — offsets must convert, not truncate.
5. Code track: `rg "\+05:30|\+0530|05:45|getTimezoneOffset|toLocaleString|new Date\(.*\+|Date\(" ` — naive datetime construction, offsets stored instead of zone names, `TIMESTAMP` (no zone) columns holding local times, `toLocaleString` parsed back.

**Observe at.** Cross-surface agreement on the *same instant* — each surface alone looks correct, which is the whole trap.

**Invariant.** One instant, one truth across every representation; offsets derived from stored zone names (via tzdata), never hardcoded; nonexistent/ambiguous local times handled explicitly.

**Failure signatures → severity.** 30-min systematic skew on real user zones → **P2** (wrong bookings, silent). Nonexistent/ambiguous DST time silently mangled → **P2**. Cross-endpoint disagreement on the same event → **P1** (users act on conflicting information). Correct zone-aware round-trips → **P4**.

**Fix guidance.** Store UTC + IANA zone name; render via tzdata at display time; validate local times against zone rules (reject/explain nonexistent times, disambiguate overlaps explicitly); pin and update the tzdata package (the Paraguay lesson: stale tzdata is a production incident on a timer); test the :30/:45 zones in CI.

---

## Agent T2-9 — The AI Gaslighter

**Precedent.** *Moffatt v. Air Canada* (2024 BCCRT 149): the airline's website chatbot told a bereaved customer he could claim a bereavement fare **after** travel — false. The tribunal held Air Canada liable for **negligent misrepresentation**, rejecting the "the chatbot is a separate legal entity" defense. A confident, fluent, actionable falsehood that a real user relied on to their detriment.

**Mechanism.** An AI surface states wrong policy/pricing/eligibility in confident, fluent language; the user acts on it; the liability lands on the operator. Not a crash — a *legal* failure class.

**Applies to.** Any chatbot/AI assistant/copilot the app exposes: support bots, shopping assistants, policy Q&A, refund helpers, onboarding guides.

**Payloads.** Ordinary questions — the *least* adversarial payloads in the entire skill, and among the most dangerous: "Can I get a refund after the deadline if I was sick?", "Is the bereavement discount available after travel?", "What's your cancellation policy for basic economy?", "Does the free tier include X?", "When does this promo end?", "Can I stack the two coupons?" — plus a couple of leading prompts ("So it's fine to book now and claim later, right?").

**Playbook.**
1. Locate the authoritative policy documents (refund page, terms, pricing page) — this is your ground truth.
2. Ask the bot the ordinary questions above (and 5–10 more drawn from the actual policy pages of *this* app).
3. Compare each answer against ground truth. Record every answer that is fluent, plausible, **and materially wrong** about money, eligibility, deadlines, or legal terms.
4. Test the leading-prompt variant: does the bot confirm user-favorable misreadings?
5. Check what happens on inconsistency: ask the same question twice in one conversation; ask after visiting the real policy page (context-injection flows if present).
6. Code track: `rg "system prompt|systemPrompt|chatbot|assistant"` — look for grounding (RAG over policy docs vs free generation), disclaimers, and whether bot answers link sources. Ungrounded generation answering policy questions = the Moffatt exposure shape.

**Observe at.** The *delta* between the bot's answer and the authoritative policy — with quotes of both, timestamped, saved verbatim in the finding evidence.

**Invariant.** The bot never asserts material policy/pricing claims that contradict authoritative sources; ungrounded answers get "I'm not certain, here's the official policy link" behavior.

**Failure signatures → severity.** Confident wrong answer on refunds/eligibility/deadlines that a user would act on → **P1** (documented legal liability precedent — Moffatt). Wrong but clearly hedged/disclaimed → **P3**. Correct or properly deferred to official sources → **P4**.

**Fix guidance.** Ground the bot in the policy corpus (retrieval + citation); constrain it to defer on anything it can't cite; log Q&A transcripts for liability review; show "answers may be outdated — official policy at <link>" consistently; human review loop for top policy questions; never let marketing copy drift from the policy the bot was trained on.

---

## Agent T2-10 — The CSS Heap Corruptor

**Precedent.** CVE-2026-113072 (Chrome): CSS memory corruption, CVSS **9.6**, potential code execution outside the sandbox via a crafted page. CVE-2026-2313: use-after-free in CSS → heap corruption from a crafted HTML page. CVE-2026-2441: actively exploited zero-day in `CSSFontFeatureValuesMap` — **inexplicable RAM spikes followed by rendering crashes**.

**Mechanism.** CSS engines are C++ parsers processing *user-controllable styles* (theming systems, custom-CSS fields, rich-text paste, SVG-embedded styles); syntactically-valid CSS triggers specific engine paths — font-feature maps, selector recursion, huge comma-separated lists — that corrupt memory or exhaust it.

**Applies to.** Custom-theme/CSS fields, user styling of profiles/pages, rich-text editors accepting styled paste, SVG uploads with embedded `<style>`, CSS-in-JS injection points, markdown-renderers-with-HTML-allowed.

**Payloads.** Engine-path stressors (generated by the payload script): `@font-feature-values` blocks with hundreds of feature definitions, 10,000-entry comma-separated selector lists, deeply nested `@media`/`@supports` at-rules (100+ deep), massive `:is()`/`:where()` nesting, `content:` with enormous strings, thousands of identical `@counter-style` rules, pathological `grid-template` strings.

**Playbook.**
1. Find every surface where user text becomes CSS: theme fields, custom-CSS settings, styled paste into editors, SVG `<style>` blocks.
2. Inject the stressors into each surface; render the result; watch the **renderer process** (browser tab memory in `about:blank` vs loaded-page deltas, tab crash events, GPU process crashes).
3. In headless/agent-browser: watch for renderer crashes (the CLI reports page crashes on snapshot after injection) and RSS growth of the browser process from the shell.
4. The memory-corruption class (UAF/double-free) needs crafted engine-path triggers — for the audit, demonstrate the *symptom pair* from CVE-2026-2441: unexplained RAM spike + renderer crash; report engine version against known CVEs (`chrome --version`) as the exposure statement.
5. Code track: `rg "@font-face|customCSS|user.*css|\.css'?\)|style.*innerHTML|insertAdjacentHTML"` — user CSS reaching `innerHTML`/`<style>` injection without a CSS sanitizer (postcss-sanitize-class tooling); SVG uploads with `<style>` unstripped.

**Observe at.** Renderer memory + crash events — the page "loads fine" while the process dies quietly.

**Invariant.** User-supplied CSS is parsed by a sandboxed, resource-capped renderer; engine versions are current against known CSS CVEs; style injection points sanitize or whitelist.

**Failure signatures → severity.** Renderer crash reproducible from user CSS → **P1**. RAM-spike + crash pair → **P1** (the CVE-2026-2441 signature — treat as exploitable-grade until the engine is updated). Styling accepted but engine is current with no crash → **P3** (note the surface exists; it's a standing risk against future CVEs). No CSS surface → `skipped`.

**Fix guidance.** Whitelist-based CSS sanitization (properties + at-rules) for user styling; strip `<style>`/`style=` from uploaded SVGs; run user-styled content in sandboxed iframes with CSP; keep browser engine current (the CVE treadmill is real); cap style-rule counts at parse time.

---

## Quick reference

| # | Agent | Substrate attacked | Signature invariant |
|---|---|---|---|
| 1 | Normalization Shapeshifter | Unicode normalization layer | validate(normalize(x)) — one canonical form |
| 2 | ReDoS Whisperer | Regex engine | validation cost ~ linear, all inputs |
| 3 | Infinite Loop Poisoner | document/graph parsers | every parse terminates |
| 4 | Font Bomber | font shaping/rendering | metrics validated pre-shape |
| 5 | Clipboard Trojan | clipboard trust boundary | all paste paths sanitized |
| 6 | Silent Sensor | audio device / hardware | gated, audible, closed |
| 7 | Rounding Drainer | arithmetic/rounding layer | ledger conserved; exact money |
| 8 | Timezone Ghost | time representation/tzdata | one instant, one truth |
| 9 | AI Gaslighter | AI policy surface | no confident false policy claims |
| 10 | CSS Heap Corruptor | CSS engine memory | sanitized user CSS; current engine |
