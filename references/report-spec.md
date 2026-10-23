# Report Spec — findings.json and the HTML Dashboard

The audit produces exactly one machine-readable artifact — `findings.json` — and one human deliverable — the HTML dashboard generated from it by `scripts/build_report.py`. This file defines both. Keep the schema exact: the dashboard generator validates and renders against it.

## findings.json

```json
{
  "audit_meta": {
    "target": "http://localhost:3000",
    "target_type": "url | repo | both",
    "repo_path": "/path/to/repo or null",
    "started": "2026-10-23T10:00:00+05:30",
    "completed": "2026-10-23T11:40:00+05:30",
    "authorization_confirmed": true,
    "consent_evidence": "User stated: 'it's my local test app, break it'",
    "auditor": "psycho-agents skill v1",
    "surface_summary": "3 forms, 1 upload, 1 CSV export, 1 payment flow, 0 AI surfaces"
  },
  "surface_map": [
    {"surface": "registration form (POST /register)", "type": "form", "fields": ["username", "display_name", "email", "password"], "flows_to": "SQLite users table, profile page, admin CSV export"}
  ],
  "findings": [
    {
      "id": "PA-001",
      "agent": "The Literal Null",
      "agent_key": "T1-1",
      "tier": 1,
      "title": "Username 'NULL' round-trips as missing in profile lookup",
      "severity": "P1",
      "confidence": "confirmed | code-audit | hypothesis",
      "precedent": "Tartaro NULL plate (2016); Christopher Null surname",
      "mechanism": "Semantic overloading of absence markers",
      "location": "POST /register → GET /profile?u=; app.py:47 (`if not username: return 'not found'`)",
      "repro_steps": [
        "POST /register with username=NULL (accepted, 200)",
        "GET /profile?u=NULL → 'user not found'",
        "GET /profile?u= (empty) → same 'user not found' response",
        "Registered 'null', 'None', 'undefined' — all accepted; 'None' and 'undefined' round-trip fine, only NULL/None collapse"
      ],
      "payload": "NULL",
      "evidence": "curl transcript: registration 200 OK; profile lookup 404 body 'user not found'; DB row exists (SELECT verified via sqlite3 CLI)",
      "invariant_violated": "NULL ≠ 'NULL' (sentinel string must be data, not absence)",
      "impact": "A user legally choosing the username NULL becomes unreachable; blank lookups may associate wrong records (Tartaro class)",
      "fix": {
        "summary": "Treat the string as data at every layer; use parameterized presence checks",
        "code": "if username is None: return not_found()  # never `if not username` on a string that may be 'NULL'"
      }
    }
  ],
  "invariant_matrix": [
    {
      "invariant": "NULL ≠ 'NULL'",
      "agents": ["T1-1"],
      "status": "fail",
      "notes": "profile lookup conflates literal 'NULL' with missing"
    }
  ],
  "agent_log": [
    {"agent": "The Literal Null", "agent_key": "T1-1", "status": "executed", "findings": 2},
    {"agent": "The Font Bomber", "agent_key": "T2-4", "status": "skipped", "reason": "no font upload or theming surface", "findings": 0}
  ]
}
```

### Field rules

- **`id`**: `PA-NNN`, sequential, stable within the audit. Findings sorted by severity then id in the report.
- **`agent_key`**: `T1-1`…`T1-13`, `T2-1`…`T2-10` — the machine key; `agent` is the display name.
- **`severity`**: exactly one of `P0|P1|P2|P3|P4` (ladder below).
- **`confidence`**: `confirmed` (fired live, observed at the failure layer), `code-audit` (sink located in code, trigger conditions documented), `hypothesis` (mechanism plausible, no live proof — use sparingly and say what would prove it).
- **`repro_steps`**: ordered, specific, executable by someone who wasn't watching. Include exact request/response pairs where possible.
- **`evidence`**: raw observations — response bodies, timing numbers, DB queries and their results, file contents. The dashboard renders it in a monospace block.
- **`invariant_violated`**: reference the invariant table (below) — this is what makes the finding *mechanism-true* rather than anecdotal.
- **`agent_log` status**: `executed | skipped | untested | blocked` — every one of the 23 agents must appear. `skipped` needs a `reason`; `untested` means the surface exists but you couldn't observe the failure layer; `blocked` means you lacked credentials/hardware/runtime.
- **`invariant_matrix`**: one row per invariant exercised (at minimum: `NULL ≠ 'NULL'`, `bytes_in == bytes_out`, `count(retries) == count(effects)`, `exported_cell_does_not_execute`, `ledger conserved`, `one instant one truth`, `every parse terminates`, `validation cost ~ linear`). Status: `pass | fail | untested`.

### Severity ladder

| Level | Meaning | Examples |
|---|---|---|
| **P0** | Data destruction, money duplication, code execution, cross-user data bleed, silent corruption on a 200 OK | utf8 `???` corruption; double charge; stored XSS executing; CSV formula reaching admin export; orphan state crossing users |
| **P1** | Crash, hang, executed injection, auth confusion, legal-liability-grade AI falsehoods, silent customer-away failures | `%s` 500; ReDoS confirmed; apostrophe-name SQL error; Moffatt-class chatbot answer; sign-up impossible with legal name |
| **P2** | Wrong-but-quiet: drift, skew, truncation, collisions, timezone 30-min errors | hardcoded UTC offset; DST overlap double-book; account collision via normalization |
| **P3** | Degraded UX, recoverable glitches, resource waste | analytics per mousemove; grapheme-splitting truncation; late bomb rejection after full decode |
| **P4** | Hardening notes and *passing controls* (defense-in-depth that is present) | correct formula guard; working idempotency key; clean rejection with actionable error |

Record P4s — passing controls are evidence for the fix-review meeting and stop the same class being re-reported next audit.

### The Real-Human multiplier

When Agent T1-13 determines a failure is reachable by a *non-adversarial* user doing something ordinary (typing their name, clicking Pay twice), bump severity one notch and say so in `impact`. Silent customer-away failures (legal name rejected at sign-up) never rate below P1.

## The HTML dashboard

Generated by:

```bash
python scripts/build_report.py <workspace>/findings.json -o <workspace>/psycho-agents-audit-<target>.html
```

Single self-contained file (inline CSS/JS, no external assets, works offline). Sections, in order:

1. **Header** — target, timestamps, duration, authorization status, surface summary.
2. **Stat cards** — findings by severity (P0–P4 counts, color-coded), agents executed/skipped/untested, invariants failed/passed.
3. **Findings, grouped by severity then agent** — each rendered as a card: severity badge, agent attribution + tier, title, precedent line ("Documented sibling: …"), mechanism, location, repro steps (ordered list), payload (code block), evidence (monospace block), invariant violated, impact, fix with code snippet, confidence chip.
4. **Invariant matrix** — the table of what the system promised vs. what it kept. This is the executive summary of the whole audit.
5. **Agent log** — all 23 agents with status; skipped reasons visible (honest scoping).
6. **Footer** — tool version, report path, timestamp.

Design language: dark audit-console aesthetic (near-black background, severity colors — P0 red, P1 orange, P2 amber, P3 blue, P4 green), monospace for payloads/evidence, sans for prose. No external dependencies so the file can be emailed, committed, or archived.
