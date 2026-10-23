![PSYCHO AGENTS](https://capsule-render.vercel.app/api?type=rect&color=0:ff6b6b,48:dc143c,100:57000d&height=180&section=header&text=PSYCHO%20AGENTS&fontSize=70&fontColor=ffffff&fontAlignY=52&animation=fadeIn)

<p align="center"><strong>Extreme edge-case auditing for web apps.</strong></p>

**Psycho Agents** is a Codex skill for auditing web applications at their sharpest edges: valid inputs that take on a different meaning when they cross a boundary such as a form, database, export, clock, or retry path.

It organizes an audit around 23 documented failure classes, including sentinel values, Unicode and normalization issues, CSV formula injection, format-string mistakes, idempotency failures, timezone drift, ReDoS, and resource-exhaustion handling. The skill produces evidence-backed findings and can render them as a self-contained HTML dashboard.

> [!CAUTION]
> Use this skill only on systems you own or have explicit written permission to test. Use staging or local environments for probes that could alter state or consume significant resources. The skill itself requires an authorization check before external testing.

## What is included

| Path | Purpose |
| --- | --- |
| `SKILL.md` | The Codex skill instructions and audit workflow. |
| `references/` | The 23-agent playbooks, code-audit guide, and report schema. |
| `scripts/payloads.py` | Payload corpus and local test-artifact generator. |
| `scripts/build_report.py` | Validates `findings.json` and produces an offline HTML report. |
| `demo/` | A deliberately vulnerable, local-only practice app and its annotated answer key. |

## Install in Codex

After publishing this repository, replace `YOUR-USERNAME` below with your GitHub username.

**macOS / Linux**

```bash
git clone https://github.com/YOUR-USERNAME/psycho-agents.git
mkdir -p ~/.codex/skills
cp -R psycho-agents ~/.codex/skills/psycho-agents
```

**Windows PowerShell**

```powershell
git clone https://github.com/YOUR-USERNAME/psycho-agents.git
New-Item -ItemType Directory -Force "$env:USERPROFILE\.codex\skills"
Copy-Item -Recurse .\psycho-agents "$env:USERPROFILE\.codex\skills\psycho-agents"
```

Start a new Codex chat, then use a prompt such as:

```text
Use $psycho-agents to audit my owned staging web app for boundary and edge-case failures.
```

## Try the local demo

The demo is intentionally vulnerable and runs only on your computer. It needs Python and Pillow:

```bash
python -m pip install Pillow
python demo/psycho_test_app_clean.py --port 8899
```

Then, in Codex:

```text
Use $psycho-agents to audit the bundled demo at http://localhost:8899. I own this local test app.
```

The `psycho_test_app_clean.py` version omits the planted-bug comments so it can be audited fairly. Review `demo/psycho_test_app.py` afterwards as the answer key.

## Development notes

The report and payload scripts use only Python's standard library. Pillow is required only for the demo. Generated databases, reports, crafted artifacts, virtual environments, and cache files are excluded by `.gitignore`.

## Before publishing

This repository intentionally does not choose a software license for you. Add a `LICENSE` file that reflects the permissions you want to give your audience before inviting reuse or contributions.

