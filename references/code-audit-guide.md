# Code-Audit Guide — Sink Recipes for the Code Track

The browser track proves failures live; the code track finds the *sinks* — the places where the failure will happen, with line-level evidence. A code hit that can't be fired live is still a finding (label it `code-audit` confidence and explain the trigger conditions); a live hit with a code location is a confirmed finding.

Run these with `rg` (ripgrep) from the repo root. Adjust patterns to the stack — the recipes below cover the common languages (JS/TS, Python, PHP, Java). **Read the surrounding code before calling a hit** — the pattern finds candidates; context decides. A `.format()` on a constant string with no user input is not a finding.

General approach: map the stack first (`package.json`, `requirements.txt`, `composer.json`, `pom.xml`, DB schema/migrations, ORM config), then run the recipes that match the stack, then trace each hit from user input to sink.

---

## 1. SQL string concatenation (→ Agent 3, T1)

```bash
rg -n "SELECT .*(\+|%s|{|\.format)" -g '!node_modules' --type-add 'src:*.js' -tsrc
rg -n '\$\w+.*(SELECT|INSERT|UPDATE|DELETE)|(SELECT|INSERT|UPDATE|DELETE).*\$\w+' --type php
rg -n 'f"(SELECT|INSERT|UPDATE|DELETE)|f'"'"'(SELECT|INSERT|UPDATE|DELETE)' --type py
rg -n '"(SELECT|INSERT|UPDATE|DELETE).*" ?\+|String\.format\("(SELECT|INSERT|UPDATE|DELETE)' -g '*.java'
rg -n '\$query\s*=|\$sql\s*=.*\.' --type php
```

**Confirm**: is user input interpolated? Parameterized calls (`?` placeholders, query builders, prepared statements) are safe — note them as passing controls. String-concat with any request-derived value → **P1 minimum** (apostrophe names break; escalate to P0 only with a live executed-injection proof).

## 2. Encoding charset traps (→ Agent 4, T1)

```bash
rg -n "characterEncoding=utf8(?!mb4)|charset=utf8(?!mb4)|utf8mb3" -g '!node_modules'
rg -n "CREATE TABLE.*(CHARSET|CHARACTER SET)=utf8(?!mb4)" -g '*.sql'
rg -n "VARCHAR\(\d+\).*utf8[^m]|COLLATE utf8_" -g '*.sql'
rg -n 'encoding="[^U]|xml\?version.*encoding="(?!UTF-8)' -g '*.xml'
```

The classic is the JDBC URL: `?characterEncoding=utf8` is `utf8mb3` — 4-byte characters (emoji, CJK Ext B) cannot be stored. Each hit → **P1/P0 code-audit finding** (the 47,000-record class is silent corruption).

## 3. Format-string sinks (→ Agent 2, T1)

```bash
rg -n "console\.log\([^\"']" -g '!node_modules' -g '!*.min.js'
rg -n "sprintf\(\s*\w|snprintf\(\s*\w|printf\(\s*\w" -g '*.{c,h,cpp,rs}'
rg -n "String\.format\(\s*\w|\.format\(\s*\w" -g '*.java'
rg -n '%\s*\(\s*\)|__mod__|\.rstrip\).*%' --type py
```

Non-literal first argument = user text can become the format. In JS, `console.log(userString)` is mostly benign in Node (format-string behavior exists but `%n` isn't a write primitive) — but `%d`/`%s` arity mismatches throw in some layers, and C bindings (native modules, logging pipelines, fluentd, firmware bridges) are the Mazda class. Report by downstream reachability.

## 4. Nested-quantifier regexes (→ T2-2)

```bash
rg -n '\([^()]*[+*][^()]*\)[+*]|\(\s*\w+\s*\|\s*\w+\s*\)[+*]|\(\.\*\)\+|\(\.+\)\*|\\w\*\\w\*|\(.*\)\{' -g '!node_modules'
rg -n 'new RegExp\(\s*[\w$.]' -g '*.{js,ts}'
```

Group-with-quantifier inside a quantifier = catastrophic backtracking candidate. `new RegExp(<variable>)` compiles user input as a *pattern* — instant ReDoS, worse. Read each hit: anchored simple patterns with bounded inputs are fine; note library usage (`validator`, `regexp*) versions where relevant.

## 5. Hardcoded offsets & naive time (→ Agent 7, T2-8)

```bash
rg -n '\+05[:]?30|\+05[:]?45|UTC\+|utc_offset\s*=|hours\s*=\s*[0-9]+\.5|330\s*\)|getTimezoneOffset'
rg -n 'new Date\(\s*\d{4}\s*,|datetime\.now\(\)(?!\s*\.astimezone)|datetime\(|utcfromdatetime|toLocaleString\(|toLocaleDateString\(' --type py -g '!*test*'
rg -n 'TIMESTAMP(?!.*(TZ|WITH TIME ZONE))' -g '*.sql'
```

Hardcoded offsets are wrong twice a year (DST) and always wrong for half-hour zones. Python `datetime.now()` without tz is naive — a time bomb at every boundary. `TIMESTAMP` columns in Postgres hold local-ish times; `TIMESTAMPTZ` is the correct type.

## 6. Missing idempotency on money/state (→ Agent 8, T1)

```bash
rg -n 'Idempotency|idempoten' -g '!node_modules'    # absence of hits is the finding
rg -n 'create.*PaymentIntent|stripe\.paymentIntents\.create|charges\.create|payment_method|checkout\.session' -g '*.{js,ts,py}'
rg -n '@app\.route\(.*(pay|order|checkout|charge)|@PostMapping\(.*(pay|order|checkout)' --type py
rg -n 'router\.(post|put)\(.*(pay|order|checkout|book|charge)' -g '*.{js,ts}'
```

For every money/state POST found, check the handler for: idempotency-key dedup, unique business keys with conflict recovery, distributed locks. Stripe SDK calls *without* the second-argument idempotency key are the documented double-charge shape.

## 7. CSV export without formula guard (→ Agent 9, T1)

```bash
rg -n 'csv|CSV' -g '*.{js,ts,py,php,java}' -l | rg -v 'node_modules'
rg -n 'csv\.writer|writerow|to_csv|Content-Type.*csv|text/csv|application/vnd\.ms-excel' -g '!node_modules'
rg -n "'|\"|escape.*csv|sanitize.*csv|formula" -g '*export*'   # look for guard functions near writers
```

Every `writerow` path reachable from user-generated text needs a formula guard (prefix `'` when first char after whitespace is `= + - @ \t \r`). Exporting with mimetype `application/vnd.ms-excel` *invites* Excel to interpret — `text/csv` plus guard is the safe pair. User-Agent/visit-log exports count too (the Shlink shape).

## 8. NULL-conflation in queries & checks (→ Agent 1, T1)

```bash
rg -n "==\s*'NULL'|=\s*'NULL'|!=\s*'NULL'|==\s*None|==\s*null|=== null|IS NULL" -g '!node_modules' -g '!*.d.ts'
rg -n 'if not \w+:|if !\w+;|\|\| ?[\'"]{2}' --type py -g '!*test*'
rg -n '\bnull\s*:\s*|sentinel|default.*null' -g '*.{js,ts}'   # schema-level sentinel overloading
```

The question each hit must answer: can a *legal string value* take this branch, or can a *missing value* skip it? String-typed columns compared against unquoted null, `if not value:` matching the literal `"None"`, and schema defaults that overload one column for both "empty" and "the string NULL" are all Tartaro-class.

## 9. Unbounded decode / bomb gaps (→ Agent 5, T1)

```bash
rg -n 'MAX_IMAGE_PIXELS\s*=\s*None|Image\.open\(|getimagesize|imagecreate|imagecreatefromstring' -g '*.{py,php}'
rg -n 'sharp\(|jimp\.|toBuffer|resize' -g '*.{js,ts}' -g '!node_modules'
rg -n 'extractall|ZipFile|unzip|tar\s+-x|archive' --type py
rg -n 'multer|formidable|filesize|maxFileSize|limit:' -g '*.{js,ts}' -g '!node_modules'
```

Pillow's `MAX_IMAGE_PIXELS = None` disables bomb protection explicitly. `Image.open()` without a pre-`size` check decodes on trust. `extractall` without caps expands nested bombs. Multer/formidable without `fileSize` limits accept anything. Each gap maps to the 56 KB PNG story.

## 10. Event handlers without throttle (→ Agent 6, T1)

```bash
rg -n "addEventListener\(['\"](mousemove|scroll|wheel|input|keydown|drag|touchmove|pointermove)" -g '*.{js,ts,vue,jsx,tsx}' -g '!node_modules'
rg -n '\.on\(['\"]mouse|\.on\(['\"]scroll' -g '*.{js,ts}'
rg -n 'throttle|debounce|requestAnimationFrame' -g '*.{js,ts}' -l   # cross-reference: which components have neither?
```

For each high-frequency handler, look for per-event: array growth (`.push` without cap), DOM writes, network calls. The finding is "handler does unbounded work per event"; throttle/debounce/rAF present = passing control.

## 11. Normalization ordering (→ T2-1)

```bash
rg -n 'normalize\(|NFKC|NFC\b' -g '*.{js,ts,py}'
rg -n 'toLocaleLowerCase|toLowerCase\(\)' -g '*.{js,ts}' -g '!node_modules'
rg -n 'collation|COLLATE' -g '*.sql'
```

Check *where* normalization sits relative to validation and uniqueness. `validate(x)` then `normalize(x)` then store = the Auth.js bug shape. Passwords passing through any normalize/lowercase = the WildFly shape.

## 12. Reference-following loops without cycle guard (→ T2-3)

```bash
rg -n 'while .*next|while .*prev|\.get\(["\']prev|follow|visit\(' -g '*.{py,js,ts}'
rg -n 'seen|visited|depth|max_(depth|iter)' -g '*.{py,js,ts}' -l   # cross-reference again
rg -n '\$ref|jsonref|resolve_ref|anchor|alias' -g '*.{js,ts,py}'
```

Every loop chasing pointers needs a seen-set or depth cap. JSON `$ref` resolvers, YAML alias expansion, PDF `/Prev` walking, GraphQL circular queries — same class.

## 13. Font & CSS trust surfaces (→ T2-4, T2-10)

```bash
rg -n '\.(ttf|otf|woff2?)|fontTools|freetype|@font-face' -g '*.{py,js,ts,php}'
rg -n 'customCSS|user_css|custom_css|style.*innerHTML|insertAdjacentHTML|dangerouslySetInnerHTML.*style|cssText' -g '*.{js,ts,jsx,tsx,vue}'
rg -n '<style|innerHTML.*<' -g '*upload*'
```

Font upload → render without structure validation; user CSS reaching `innerHTML`/`dangerouslySetInnerHTML`/`cssText` without a sanitizer; SVG upload keeping `<style>` blocks — all standing exposures against engine CVEs.

## 14. Money arithmetic on floats (→ T2-7)

```bash
rg -n 'float|parseFloat|Number\(|\.toFixed\(|Math\.round' -g '*.{js,ts}' | rg 'price|amount|total|balance|fee|charge|discount|tax' 
rg -n 'float\(|Decimal\(|round\(' --type py | rg 'price|amount|total|balance|fee|charge|discount|tax'
rg -n 'FLOAT|DOUBLE|REAL' -g '*.sql' | rg 'price|amount|total|balance|fee|charge|discount|tax'
```

Money as binary float (column type or JS number on a money path) is the Vancouver/Vancouver-adjacent drift class. Correct: integer minor units or DECIMAL/NUMERIC columns with explicit rounding policy. `parseFloat` on a money input followed by arithmetic = the Pyth coercion shape; silent `Number(user_input)` → `NaN` → `0` flows are the silent-zero bug.

## 15. Retry layers (→ Agent 12, T1)

```bash
rg -n 'retry|retries|backoff|exponential|circuit.?breaker|resilience' -g '!node_modules' -g '!*.lock' -i
rg -n 'setTimeout\(\s*\w+,\s*\d+\)|sleep\(\s*\d+\s*\)' -g '*.{js,ts,py}'    # fixed delays near retry keywords
rg -n 'while\s*\(.*(?:true|attempts|retries).*\)' -g '*.{js,ts,py}'
```

Count the layers: frontend fetch wrapper + API gateway + service client + DB driver each retrying = the twelve-services story. Fixed delays without jitter = the thundering herd. `while(true)` retry loops without breakers = outage amplifiers.

## 16. Electron / desktop trust bridges (→ T2-5)

```bash
rg -n 'nodeIntegration|contextIsolation|webSecurity|sandbox:' -g '*.{js,ts,json}'
rg -n 'clipboardData|onpaste|paste' -i -g '*.{js,ts,jsx,tsx}'
rg -n 'ipcMain\.handle|ipcRenderer\.invoke' -g '*.{js,ts}'
```

`nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false` are each a finding. Paste handlers branching on custom MIME flavors with sanitizer-skips are the SiYuan CVE shape; ipcMain handlers reachable from renderer-pasted content complete the path.

## 17. AI surfaces (→ T2-9)

```bash
rg -n 'systemPrompt|system_prompt|chatbot|assistant|completion\.create|chat\.completions|anthropic|openai' -g '*.{js,ts,py}' -g '!node_modules'
rg -n 'temperature|retrieval|RAG|grounding|disclaimer' -g '*.{js,ts,py}'
```

For each AI surface: is generation grounded in a policy corpus (retrieval) or free? Do answers carry disclaimers/source links? Are transcripts logged? Ungrounded + policy questions + no disclaimer = the Moffatt exposure shape.

---

## Attribution cheat-sheet

| Recipe | Finding agent |
|---|---|
| 1 SQL concat | T1-3 Accidental Injector |
| 2 charset | T1-4 Four-Byte User |
| 3 format strings | T1-2 Format Specifier |
| 4 nested quantifiers | T2-2 ReDoS Whisperer |
| 5 hardcoded time | T1-7 Clock Disagreer / T2-8 Timezone Ghost |
| 6 idempotency | T1-8 Retry Trigger |
| 7 CSV guard | T1-9 Spreadsheet Payload |
| 8 NULL conflation | T1-1 Literal Null |
| 9 decode caps | T1-5 Decompression Bomb |
| 10 event throttle | T1-6 Event Flood |
| 11 normalization order | T2-1 Normalization Shapeshifter |
| 12 cycle guards | T2-3 Infinite Loop Poisoner |
| 13 font/CSS | T2-4 Font Bomber / T2-10 CSS Heap Corruptor |
| 14 money floats | T2-7 Rounding Drainer |
| 15 retry layers | T1-12 Retry Storm |
| 16 Electron bridges | T2-5 Clipboard Trojan |
| 17 AI grounding | T2-9 AI Gaslighter |

Every code hit needs three things recorded in the finding: **file:line**, the **trace** (how user input reaches it), and the **confidence** (`confirmed` if fired live, `code-audit` otherwise).
