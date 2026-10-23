---
name: psycho-agents
description: Extreme edge-case auditing for websites and web apps using 23 research-backed "psycho agents" — each one a documented production failure class (the NULL license plate, the Mazda %In format-string crash, 47,000 emoji-corrupted records from utf8 vs utf8mb4, 56KB PNG decompression bombs, CSV formula injection, double-charge idempotency failures, DST/timezone drift, ReDoS, Unicode normalization bypasses). Use this skill whenever the user wants to stress-test, chaos-test, or fuzz a website/app at its edges; find extreme edge cases before real users hit them; test NULL/Unicode/format-string/timezone/idempotency/rounding handling; run adversarial or "psycho user" QA; asks "try to break my site", "audit my app for edge cases", "what happens if a user does X"; or mentions sentinel values, Bobby Tables, mojibake, decompression bombs, or wants a pentest-style audit report with severity-ranked findings. Runs a hybrid live-probe + source-code inspection and emits an HTML audit dashboard.
---

# Psycho Agents — Extreme Edge-Case Audit

## The mental model

In 2016 Joseph Tartaro registered the vanity plate `NULL`. The DMV database later resolved *every blank license-plate field* to the string `'NULL'`, and every blank-plate citation routed to him — $12,049 in fines he didn't owe. The input was perfectly legal. The system failed because it conflated `NULL` (absence) with `'NULL'` (a four-character string).

That is the whole game. **Psycho agents are not malicious users — they are legal inputs that become semantically overloaded when they cross a boundary** (human form → database, track metadata → C parser, app field → spreadsheet, one system's clock → another's clock). Your job when running this skill is to *become* those inputs, at the exact boundaries where each documented failure class lives, and then verify the invariant the real incident violated.

Three principles separate this from generic QA:

1. **Mechanism-first, not persona-first.** Each agent is a documented failure class (semantic overloading, format-string misinterpretation, encoding truncation, retry re-entry...), not a mood. The agent roster in the references is the *reporting taxonomy*; you attribute each finding to the agent whose mechanism you exercised.
2. **Observe at the layer where the failure actually occurred.** A silent utf8→`???` corruption returns HTTP 200. A CSV formula injection only fires when an admin opens the export in Excel. A decompression bomb kills the worker, not the response. Never conclude "passed" from a 200 OK alone — round-trip the value, compare bytes, check timing, read the code path.
3. **Verify the invariant, not the absence of an error.** Every agent carries an invariant (`NULL ≠ 'NULL'`, `bytes_in == bytes_out`, `count(submissions) == 1`, `image.dimensions ≤ safe_limit`, `exported_cell_does_not_execute`). An audit finding is an invariant violation with evidence. An untested invariant must be reported as `untested` — never silently upgraded to `passed`.

## Hard rules — read before doing anything

1. **Authorization gate comes first. Before probing any target, the user must explicitly state they own it or have written permission to test it.** If they haven't said so in the conversation, ask. If they refuse or hedge, stop and explain why (unauthorized testing is illegal in most jurisdictions, and these payloads can corrupt data, double-charge cards, and crash servers). A target that is localhost, an obvious dev box, or a repo in the user's workspace is presumptively owned — but external URLs always need the confirmation. Record the consent statement in `findings.json → audit_meta.authorization_confirmed`.
2. **Destructive probes only on owned/staging targets.** Payment double-fire, retry storms, decompression bombs, and abandon-replay flows can cause real damage. If the user describes a target as production but owned, ask whether there is a staging instance; if not, run the destructive agents in *read-only mode*: locate the vulnerable code path or the missing control (e.g., no idempotency key in the request) and report it as a code-audit finding with the mechanism explained, without firing the live shot.
3. **Rate-limit yourself.** No more than a few requests per second, no true "storms" — the Retry Storm agent demonstrates the *pattern* (a burst of ~20 rapid requests is enough evidence) rather than an actual outage-scale flood. The goal is a bug report, not an outage.
4. **Report honestly.** `skipped` (no matching surface), `untested` (couldn't observe), and `blocked` (needs credentials/hardware you lack) are legitimate, valuable statuses. A finding without evidence is a hypothesis — label it as such.

## Workflow — six phases

### Phase 0 — Consent gate (30 seconds)

If the target is external (not localhost / not a workspace repo), get the ownership statement. Write it down. If consent is unclear, ask one question and stop until answered.

### Phase 1 — Recon & surface map

Build a map of every input boundary before touching anything. Save it to the workspace as `surface_map.md`:

- **Entry points**: pages, routes, forms, search boxes, filters, sort orders
- **Text fields** (and where each one flows: DB? template? email? PDF? export?)
- **File uploads** (images? PDFs? fonts? any filetype restriction?)
- **Auth surfaces** (login, register, password reset, session/token handling)
- **Money/state flows** (checkout, payment, subscription, delete-account, permission changes)
- **Exports** (CSV/Excel/PDF downloads — the CSV-injection surface)
- **APIs** (REST/GraphQL endpoints, request bodies, headers like User-Agent)
- **Client-heavy components** (charts, feeds, rich-text editors, infinite scroll, websockets)
- **Third-party boundaries** (email sending, OCR, Bluetooth/audio-adjacent features, AI chatbots)

For a repo target: read the routes/controllers/schema first — this tells you where the sinks are. For a URL target: crawl pages with the browser, inspect forms and network traffic. For both: cross-reference — the URL tells you the surface, the code tells you the sink.

### Phase 2 — Code track (if a repo is available)

Read `references/code-audit-guide.md` and sweep the codebase with its grep recipes. This track alone reliably finds: SQL string concatenation, `characterEncoding=utf8` vs `utf8mb4`, nested-quantifier regexes, non-literal format strings, hardcoded UTC offsets, missing idempotency keys, CSV exports without formula escaping, and `NULL`-equality bugs. Record findings as you go — a code hit is evidence for the browser track to confirm live.

No repo? Skip to Phase 3 and rely on black-box probing + the app's observable behavior.

### Phase 3 — Live track (if a reachable URL exists)

Use browser automation (the `agent-browser` CLI if installed: `agent-browser open <url>` → `snapshot -i` → `fill @ref "payload"` → `click @ref`; otherwise Python `requests`/`curl` for API-level probing). Note which surfaces need a real browser (clipboard, audio routing, CSS engine, mousemove floods) — those execute only if a browser runtime is available.

### Phase 4 — Run the 23 agents

Read `references/agents-tier1.md` (13 app-layer agents) and `references/agents-tier2.md` (10 substrate-layer agents). Full playbooks live there — precedent, payloads, procedure, observation layer, invariant, fix guidance. Don't try to hold all 23 in your head; execute them in **sweeps**:

| Sweep | Agents | What happens |
|---|---|---|
| **A. Text-payload sweep** | T1-1 Literal Null, T1-2 Format Specifier, T1-3 Accidental Injector, T1-4 Four-Byte User, T1-9 Spreadsheet Payload, T1-11 Length Illusionist, T2-1 Normalization Shapeshifter, T2-2 ReDoS Whisperer | One pass over every text surface with the full payload corpus (from `scripts/payloads.py`), then round-trip verification of every stored value |
| **B. File-upload sweep** | T1-5 Decompression Bomb, T1-4 (file surface), T2-3 Infinite Loop Poisoner, T2-4 Font Bomber | Upload crafted artifacts to every upload surface; watch for crashes, hangs, OOM |
| **C. State & timing sweep** | T1-7 Clock Disagreer, T1-8 Retry Trigger, T1-10 Orphan, T2-8 Timezone Ghost | Double-submits, abandon-and-return, boundary timestamps, token-expiry replay |
| **D. Browser-runtime sweep** | T1-6 Event Flood, T2-5 Clipboard Trojan, T2-6 Silent Sensor, T2-10 CSS Heap Corruptor | Needs a real browser; event floods, paste handlers, WebAudio/context lifetime, crafted CSS into any user-styling surface |
| **E. Backend-behavior sweep** | T1-12 Retry Storm, T2-7 Rounding Drainer | Rapid repeated calls to state-changing endpoints (gently!), repeated small-value conversions watching for drift |
| **F. Human-surface sweep** | T1-13 Real Human, T2-9 AI Gaslighter | Legitimate-user strings everywhere; if there's a chatbot, ask policy questions and compare answers to actual policy |
| **G. Code-audit only** | every agent's code-track checklist | Findings from Phase 2, attributed to their agents |

Grouping by execution mechanism (instead of running agents one-by-one) means each browser session covers 8 agents at once — the payloads are just strings in a corpus. Attribution happens at *finding* time: when `NULL` round-trips wrong, that's a T1-1 finding; when `👨‍👩‍👧‍👦` comes back as `???`, that's T1-4.

**Applicability**: run every agent, but agents with no matching surface get status `skipped` + reason ("no upload surface", "no AI chatbot", "no browser runtime"). Skipping is honest scoping, not failure — record it in `agent_log`.

### Phase 5 — Findings & report

1. Write `findings.json` following the schema in `references/report-spec.md` (also defines the P0–P4 severity ladder and the invariant matrix).
2. Run the report generator:
   ```bash
   python <skill-dir>/scripts/build_report.py <workspace>/findings.json -o <workspace>/psycho-agents-audit-<target>.html
   ```
3. Open/verify the dashboard renders (check the HTML loads and findings appear).

### Phase 6 — Debrief the user

Tell them: the report path, the P0/P1 count, the single most interesting invariant violation found, which agents were skipped and why, and what to fix first. Keep it short — the dashboard carries the detail.

## Context economy

A full 23-agent audit reads a lot of files and generates a lot of output. If you are executing with a bounded context (as a subagent or deep in a long session), keep working memory lean: read the reference files in the order the phases need them rather than all at once (Phase 2 needs only the code-audit guide; Phase 4 needs the two agent rosters), redirect large payload dumps to files instead of reading them fully into context, record observations into the workspace files as you go rather than holding them, and prefer one representative payload per class per surface over exhaustive repetition — the sweep architecture already covers the corpus; repetition adds tokens, not findings. If the target is small, expect most agents to finish quickly and don't pad.

## Payload & artifact generation

`scripts/payloads.py` is the corpus. Use it rather than typing payloads by hand — consistency matters because the *same* payload set across surfaces is what makes findings comparable.

```bash
python scripts/payloads.py list                       # all payload sets
python scripts/payloads.py get null-set               # prints JSON: value, note, origin story
python scripts/payloads.py get all --format text      # everything, one payload per line
python scripts/payloads.py make bomb-png --out bomb.png        # 56KB-style PNG, declares 20000×20000
python scripts/payloads.py make zip-bomb --out bomb.zip        # nested archive, small file, huge expansion
python scripts/payloads.py make cyclic-pdf --out loop.pdf      # PDF whose xref /Prev points at itself
```

Read a payload's `origin` field before firing it — knowing *why* `L'Aquila` breaks things (apostrophe in a legal Italian town name) makes your findings better, and the origin strings are the story you tell in the report.

## Severity ladder (full definitions in references/report-spec.md)

- **P0** — data destruction, money duplication, code execution, unrecoverable corruption (silent utf8 corruption, double charge, formula execution)
- **P1** — crash, hang, injection that executes, authentication confusion
- **P2** — wrong-but-quiet behavior: drift, 30-minute timezone skew, truncation, account collision
- **P3** — degraded UX, recoverable glitches, resource waste
- **P4** — hardening notes: missing defense-in-depth even where no live exploit succeeded

## What "done" looks like

The audit is complete when: every one of the 23 agents has a status (`executed` / `skipped` / `untested` / `blocked`), every finding has evidence and an invariant reference, `findings.json` validates, the HTML dashboard renders, and the user knows their top three fixes.

## File map

| File | Read when |
|---|---|
| `references/agents-tier1.md` | Phase 4 — the 13 app-layer agent playbooks |
| `references/agents-tier2.md` | Phase 4 — the 10 substrate-layer agent playbooks |
| `references/code-audit-guide.md` | Phase 2 — grep recipes per failure class |
| `references/report-spec.md` | Phase 5 — findings.json schema, severities, invariant matrix |
| `scripts/payloads.py` | Phases 3–4 — payload corpus + crafted artifact generation |
| `scripts/build_report.py` | Phase 5 — findings.json → HTML dashboard |
| `demo/psycho_test_app.py` | First run / demonstration — a deliberately vulnerable practice target with its own answer key; audit the `_clean` copy and compare against the annotated original |
