# Claude Skills and Prompts
A small collection of Claude and Claude Code skills for aiding cybersecurity analysis work. Skills are designed for Claude Code but will fallback to other methods and work with Claude Desktop as well but without as much information 

| Tool | Purpose |
|---|---|
| [infragrapher](#infragrapher) | Maps attacker infrastructure from a seed of a domain, URL, or IP address, finds novel indicators, and creates a 3d graph |
| [malware-analysis](#malware-analysis-1) | Static and dynamic malware analysis and reverse engineering using sogen and uv |
| [netcheck](#netcheck) | Network OSINT investigation |
| [hashcheck](#hashcheck) | File and Hash OSINT investigation |
| [bugbounty_prompt](#bugbounty_prompt) | Turns a local LLM or Kimi k3 into an automated pen tester of a given site, domain or scope |


## Attacker Infrastructure Discovery and Graphing
[infragrapher](#infragrapher) is an Agent Skill that maps the infrastructure surrounding a single seed indicator — a domain, URL, or IP address — and returns an interactive 3D graph alongside a written analyst briefing. It fingerprints the seed across registration, DNS, hosting, certificate transparency, passive DNS, and published email-authentication records, and where the runtime permits direct connections it also collects JARM TLS fingerprints, Shodan-compatible favicon hashes, SubjectPublicKeyInfo pins, OpenType font licensing metadata, normalized SVG geometry hashes, declared source maps, build identifiers, and custom error-page hashes. It pivots on those fingerprints to discover infrastructure the same operator runs, rating each link strong, medium, or weak: a reused DKIM public key or a matching public-key pin implies shared key material, whereas a shared content delivery network implies nothing. Expansion runs two hops from the seed under a 40-to-70-node budget, and the second hop expands only strongly linked domains and IP addresses — never shared-attribute nodes such as favicon hashes or autonomous system numbers, which fan out to thousands of unrelated hosts. Six standard-library Python scripts implement the workflow: collect.py runs the passive lookups in parallel, opsec_check.py reports the egress IP address a target would log, fingerprint.py gathers the active signals behind a required acknowledgment flag, build_graph.py renders the graph, diff_graph.py compares two runs to support monitoring, and export_ioc.py emits STIX 2.1, MISP, CSV, or blocklist output with confidence preserved. The skill detects whether its runtime has shell network access and degrades to a fetch-tool-only path when it does not, and it constrains itself to declared references and published records rather than guessing at unlinked paths, recording every source it could not reach in the briefing rather than presenting partial coverage as complete.

## Malware Analysis
[malware-analysis](#malware-analysis-1) reverse-engineers a supplied binary (PE, DLL, driver, or shellcode) to determine whether it is malicious and how. It runs static triage — hashing, PE parsing, section entropy, import and string extraction, packer heuristics — then detonates the sample inside the sogen user-space emulator to unpack later stages, resolve runtime-loaded imports, and dump decrypted strings from memory, recursing through each stage until nothing unpacks further. It maps the resulting capabilities, anti-analysis techniques, and C2 infrastructure to MITRE ATT&CK IDs and writes a defanged report.md leading with a verdict (malicious, benign, or inconclusive) and confidence. The sample runs only under emulation and all tooling runs in disposable uv environments, so the code never executes on the host.
### Usage
The skill creates a copy of the sogen root directory under /temp/ and copies the payload there for emulation, it assumes a golden-image root at /Users/user/root and will need to be updated in kind. In the prompt tell it:
* The full path to the root directory
* The full path of the working directory it should use
* The full path to the sample

## Network OSINT Investigation
[netcheck](#netcheck) investigates a single IP address or domain and returns a security analyst's briefing — a risk verdict (Low, Medium, or High), a one-paragraph summary, and a facts table. It pulls together ownership provenance, DNS records, hosting and ASN, exposed services and CVEs, TLS certificate history, and reputation data into one picture, weighting registration age and ownership changes most heavily. It's passive reconnaissance only: it reads what public databases already know and never scans, exploits, or logs into a target.

## Hash OSINT Investigation
[hashcheck](#hashcheck) does the same for a single file, identified by its hash (MD5, SHA-1, or SHA-256) — returning a malware analyst's briefing with a verdict (Benign, Suspicious, Malicious, or Unknown), a summary, and a facts table. It weighs multi-engine detection consensus, code-signing status, file structure like PE section entropy and packing, and sandbox behavior. Like netcheck, it's read-only: a records check on the fingerprint that never detonates or runs the sample.

Both this and netcheck follow the same design — try a bundled script when the shell has internet, fall back to WebFetch in sandboxes, degrade gracefully when a source is unavailable, and write the summary in Google technical writing style (conclusion first, active voice, short sentences).

## Bugbount and VDP prompt
[bugbounty_prompt](#bugbounty_prompt) a fully autonmous LLM driven scoped, authorization-gated web assessment. It accepts two modes: a program policy URL, or a user-authorized target. It first derives engagement/CONTRACT.md and builds a source-annotated scope.txt. It blocks all traffic until it verifies scope and authorization. It then runs ordered phases: passive reconnaissance, JavaScript and route mining, subdomain and HTTP enumeration, unauthenticated injection and access-control probes, framework-specific checks, and optional two-account authenticated testing. Each probe is manual, capped at three requests per second, and stops at the detection differential or out-of-band (OOB) callback. Every finding clears an impact-only validation gate — cross-account proof, body diff, and multi-stack reproduction — before it lands in FINDINGS.md. The prompt stores sanitized evidence under engagement/ and enforces the program's disclosure terms.

# Skills
## infragrapher

Map the infrastructure behind a domain, URL, or IP address, and render it as
an interactive 3D graph.

infragrapher is a skill for Claude Code and other runtimes that load
[Agent Skills](https://code.claude.com/docs/en/skills). You give it one
indicator. It fingerprints the host, pivots outward to find infrastructure
the same operator runs, and returns two deliverables: a self-contained HTML
graph and a written analyst briefing.

### Why

A single-indicator lookup tells you about one host. infragrapher answers the
next question: what else belongs to whoever runs this?

It pivots on signals that are hard to rotate and rarely checked.

| Signal | What a match proves |
|---|---|
| DKIM public key | Shared private key material |
| SPKI certificate pin | Same key pair, and it survives certificate reissuance |
| DMARC `rua` address | One mailbox receives both domains' reports |
| Source map | Shared developer paths or internal package scopes |
| Build ID | The same CI pipeline deployed both sites |
| Favicon or JARM hash | Same kit, panel, or TLS stack |
| Font `name` table | Who licensed the typeface |
| SVG geometry hash | Same artwork, even after recolouring |

Every link carries a confidence rating of strong, medium, or weak. A shared
certificate proves common ownership. A shared content delivery network (CDN)
proves nothing, and the graph shows that difference.

### Requirements

- Python 3.8 or later. The scripts use only the standard library.
- A runtime that loads Agent Skills, such as Claude Code.
- Optional: `pyjarm` for JARM fingerprints, `brotli` to read WOFF2 font
  metadata. Both degrade cleanly when absent.

### Install

```bash
git clone https://github.com/<you>/infragrapher.git
cp -r infragrapher ~/.claude/skills/
```

### Use

Ask your agent in plain language:

> Map the infrastructure connected to example.com and show me a graph.

To run the scripts directly:

```bash
# Passive collection. Contacts no target.
python3 scripts/collect.py example.com --json collect.json

# Check which IP a target would log, before any active check.
python3 scripts/opsec_check.py

# Active fingerprint, after you confirm the egress address.
python3 scripts/fingerprint.py example.com --ack-egress --json fp.json

# Write graph.json from your findings, then render it.
python3 scripts/build_graph.py graph.json out.html --title "infragrapher: example.com"
```

`build_graph.py` renders an existing file. It does not collect data. Run
`python3 scripts/build_graph.py --example graph.json` for a starter template.

### Scripts

| Script | Purpose |
|---|---|
| `collect.py` | Runs every passive lookup in parallel, returns one JSON object. |
| `opsec_check.py` | Reports the public IP a target would log and judges whether it looks like a virtual private network (VPN). |
| `fingerprint.py` | Collects active signals: JARM, favicon, SPKI, fonts, SVG, source maps, build IDs, error pages. |
| `build_graph.py` | Renders a graph JSON file as a self-contained 3D HTML page. |
| `diff_graph.py` | Compares two graphs and marks what changed. |
| `export_ioc.py` | Exports STIX 2.1, MISP, CSV, or a plain blocklist. |

### Output

The HTML graph supports rotation, zoom, hop filters, search, a timeline
scrubber, screenshots, per-node verdicts, and a commonalities panel.

Expansion runs two hops from the seed under a 40-to-70-node budget. The
second hop expands only strongly linked domains and IP addresses, never
shared-attribute nodes such as favicon hashes or autonomous system numbers,
which fan out to thousands of unrelated hosts.

### Two environment tiers

Run `collect.py` to detect which tier applies.

| Capability | Tier A: shell with internet | Tier B: fetch tool only |
|---|---|---|
| Parallel collection | Yes | No |
| Active fingerprints | Yes | No |
| Email authentication, passive DNS, certificates, WHOIS | Yes | Yes |
| Graph, timeline, diff, export | Yes | Yes |

Tier B still supports a complete investigation, and the briefing records
what it could not reach.

### Scope

Most lookups are passive and never contact the target. Some checks connect
directly, including fetching the homepage, the favicon, and TLS handshakes.
For those, `fingerprint.py` requires `--ack-egress`, and the skill asks you
to confirm the result of `opsec_check.py` first.

infragrapher does not scan port ranges, brute-force names or credentials,
authenticate, or send payloads. It follows source maps only where the
JavaScript declares them; it never guesses at unlinked paths.

### Optional API keys

`collect.py` reads these from the environment and reports which were absent.
All are optional.

`VT_API_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`, `SECURITYTRAILS_API_KEY`,
`CERTSPOTTER_API_KEY`

### Repository layout

```
infragrapher/
├── SKILL.md            # Workflow the agent follows
├── references/         # Sources, fingerprint signals, graph schema
├── scripts/            # The six scripts above
└── evals/              # Test cases
```

### Interpreting results

- **A clean reputation is not evidence of safety.** Reputation feeds record
  observed mass abuse. Targeted infrastructure is retired before scanners
  sample it, so zero detections is expected for the most dangerous hosts.
- **Weak links are not ownership.** Shared CDN, cloud, or autonomous system
  membership connects millions of unrelated hosts.



## malware-analysis

malware-analysis reverse-engineers a supplied binary to determine whether it is malicious or benign and produces a comprehensive analyst report. It unpacks multi-stage payloads, recovers encrypted strings, resolves dynamic imports, catalogues evasion techniques, extracts command-and-control (C2) infrastructure, and writes it all to `report.md`.

This is defensive work. The deliverable is understanding — every indicator it surfaces helps someone detect or contain the threat, never redeploy it.

### When it triggers

The skill runs when you hand over a file, sample, executable, DLL, driver, or shellcode blob and ask Claude to analyze it, reverse engineer it, unpack it, determine if it is malware, decrypt its strings, resolve its imports, find its C2, or write a malware report — even without the word "malware." It also triggers when you ask it to triage a suspicious download or email attachment.

### Containment

Two rules keep the sample and its tooling from touching the host:

- **The sample never runs on the analysis host.** The only place it executes is inside **sogen**, a Windows user-space emulator that runs the code at the syscall level with full visibility and no access to the real machine.
- **Every helper runs in a disposable `uv` environment.** Static parsers, the sogen harness, and YARA all run through `uv run --with ...`, which builds an ephemeral environment and leaves the host interpreter untouched — never a bare `pip install`.

All indicators are defanged everywhere they appear (`hxxp://`, `evil[.]com`, `10[.]0[.]0[.]5`) so nothing in the report can be clicked or resolved by accident. If sogen cannot be obtained, the skill falls back to static-only analysis and states the limitation rather than detonating on the host.

### How the analysis flows

The work runs in phases, static before dynamic, unpacking recursively:

1. **Static triage** — hash the sample, parse the PE (sections, entropy, imports, signature, timestamp), extract strings, and flag packer and evasion tells.
2. **Form hypotheses** — decide what the sample is and write the questions dynamic analysis must answer.
3. **Dynamic analysis in sogen** — detonate under emulation to unpack later stages, resolve runtime imports, and recover decrypted strings from memory.
4. **Recurse** — each dumped stage goes back through the pipeline until nothing unpacks further.
5. **Catalogue** — map capabilities, evasion, and C2 to technique families and MITRE ATT&CK IDs.
6. **Write the report** — synthesize everything into `report.md`.

### Output

The deliverable is always `report.md`. It leads with a **determination** — a verdict of `Malicious`, `Benign`, or `Suspicious / inconclusive`, paired with a confidence level (high, medium, or low) and the evidence behind it. A named family is given only when the evidence supports it; otherwise the family is marked unidentified rather than guessed.

The report covers, at minimum: determination, executive summary, sample metadata, per-stage analysis, capabilities, anti-analysis techniques, command and control, indicators of compromise, MITRE ATT&CK mapping, and detection and response recommendations. It is written in Google technical-writing style — conclusion first, short active sentences, acronyms expanded on first use, tables for structured data.

### Requirements

- **sogen** — the Windows user-space emulator, installed on demand via `uv run --with sogen`. Needs an emulation root (real Windows system DLLs); the harness copies the canonical root to a disposable `/tmp/root` on first run, or fetches `https://sogen.dev/root.zip`.
- **uv** — creates the disposable Python environments every helper runs in.
- **A shell with egress** — to install packages and fetch the emulation root.

Optional Python packages (`pefile`, `capstone`, `yara-python`, `signify`) are added per-command; the triage script degrades cleanly when any are unavailable.

### Files

| Path | Purpose |
|---|---|
| `SKILL.md` | Full workflow, containment rules, and report requirements. |
| `scripts/static_triage.py` | Safe static triage: hashing, PE parsing, entropy, strings, packer heuristics, YARA, Authenticode. Run first, every time. |
| `scripts/sogen_harness.py` | Adaptable sogen harness with common hooks and a memory-dumping helper for capturing unpacked stages. |
| `assets/rules/triage.yar` | Bundled YARA rules for static triage. |
| `references/sogen-usage.md` | How to drive sogen for unpacking, import resolution, and string recovery. |
| `references/analysis-playbook.md` | Technique catalogue: packers, string encryption, anti-analysis families, capabilities, and C2 shapes. |
| `references/report-template.md` | The exact `report.md` structure and Google-style tone. |

### Scope

malware-analysis studies an existing artifact to understand and defend against it. It does not build, improve, or repackage anything harmful, and it never runs the sample outside emulation.

## hashcheck

hashcheck runs a passive OSINT investigation on one file hash (MD5, SHA-1, or SHA-256) and returns a malware analyst's briefing: a risk verdict, a one-paragraph summary, and a facts table.

It reads only what public malware databases already know about a hash. It never detonates the sample, downloads and runs it, submits it without saying so, or contacts attacker infrastructure.

### When it triggers

hashcheck runs when you type `hashcheck <hash>`, or when you paste a hash or point at a file and ask Claude to "investigate", "look up", "check the reputation of", "analyze", "run OSINT on", "is this file safe", "is this malware", or "should I trust this binary". It also triggers when you upload or name a file to triage.

### Usage

```
hashcheck 44d88612fea8a8f36de82e1278abb02f
hashcheck /path/to/suspicious.exe
hashcheck <hash1> <hash2> <hash3>
```

Give it a bare hash, a file, or several hashes at once. For a file, hashcheck computes all three digests before looking anything up and reports the SHA-256 so you can confirm the match. For a batch, it leads with a one-line summary table, then gives the full briefing only for hashes that warrant it.

### What the verdict rests on

hashcheck weighs four signals, in this order:

- **Consensus detection** — how many reputable engines flag the file and what family they agree on. The strongest single signal.
- **Code-signing and provenance** — who signed the file and whether the certificate is valid. A broken, expired, revoked, or mismatched signature is worse than none.
- **File structure** — for Windows PE files, section entropy, packer names, import tables, and type/extension mismatches that betray packing or obfuscation.
- **Sandbox behavior** — dynamic-analysis verdicts, dropped files, network indicators, and YARA/Sigma matches. Used when the static picture is ambiguous.

A hash no database has seen is **unknown**, not clean. hashcheck says so and reasons from structure and signing instead.

### Output

hashcheck returns three parts, in order:

1. **Verdict** — one of `Benign`, `Suspicious`, `Malicious`, or `Unknown`.
2. **Summary** — one paragraph of three to five sentences in Google technical writing style.
3. **Facts table** — hashes, file type, detection score, signature, packing, sandbox verdict, and the sources it reached.

An optional Notes section lists caveats or leads for human follow-up.

### Network access

hashcheck reaches public malware-intel APIs through one of two paths:

- **The bundled script** `scripts/hashcheck.py` — runs every lookup at once where the shell has internet and API keys are set. Uses the richer VirusTotal v3 endpoints (`pe_info`, `signature_info`, sandbox verdicts), MalwareBazaar, Hybrid Analysis, and Joe Sandbox.
- **The WebFetch tool** plus `WebSearch` — used in Cowork and other sandboxes with no shell egress. Limited to VirusTotal's v2 endpoint for the multi-engine verdict plus web search for corroboration; PE sections, entropy, and signing detail are usually unavailable.

hashcheck tries the script first when a shell exists, then falls back to WebFetch if the shell has no egress.

### API keys

hashcheck reads optional keys from environment variables. Sources without a key degrade to their free tier or are skipped.

| Variable | Source |
|---|---|
| `VT_API_KEY` | VirusTotal |
| `MALWAREBAZAAR_API_KEY` | MalwareBazaar |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis |
| `JOE_SANDBOX_API_KEY` | Joe Sandbox |

Confirm exact variable names in `references/sources.md`.

### Files

| Path | Purpose |
|---|---|
| `SKILL.md` | Workflow, scoring rules, and output format. |
| `scripts/hashcheck.py` | Runs all lookups and prints one JSON object. Accepts a hash or a file path. |
| `references/sources.md` | Full endpoint catalog, auth details, and failure behavior. |

### Scope

hashcheck is passive, defensive reconnaissance only — a records check on a fingerprint. If you ask it to execute or actively probe a sample, it declines that part and explains that it is read-only.



## netcheck

netcheck runs a passive OSINT investigation on one IP address or domain and returns a security analyst's briefing: a risk verdict, a one-paragraph summary, and a facts table.

It reads only what public databases already know. It never scans, exploits, brute-forces, logs in, or sends payloads to the target.

### When it triggers

netcheck runs when you type `netcheck <target>`, or when you ask Claude to "investigate", "look up", "check the reputation of", "profile", "run OSINT on", "who owns", or "is this safe" for any IP, domain, hostname, or URL. A pasted URL works too; netcheck reduces it to its host.

### Usage

```
netcheck 8.8.8.8
netcheck evil-domain.com
netcheck https://sketchy.example.com/login
```

### What it checks

netcheck synthesizes seven signals into one picture:

- **Ownership provenance** — registration age, recent registrar or registrant changes, and registrar reputation. Weighted most heavily.
- **DNS** — A, AAAA, MX, NS, TXT, and SOA records.
- **Hosting** — geolocation, ISP, and ASN, graded from established cloud through commodity VPS to bulletproof hosts.
- **Exposed services** — open ports and known CVEs.
- **TLS certificate** — issuer, first-issuance date, subdomain sprawl, and served-vs-logged mismatches from Certificate Transparency logs.
- **Reputation** — VirusTotal, Shodan tags, and web-search findings.

Each source degrades independently. netcheck reports gaps rather than stopping.

### Output

netcheck returns three parts, in order:

1. **Verdict** — one of `Low`, `Medium`, or `High`.
2. **Summary** — one paragraph of three to five sentences in Google technical writing style.
3. **Facts table** — resolved values for each signal, plus the sources it reached.

An optional Notes section lists caveats or leads for human follow-up.

### Network access

netcheck reaches public APIs through one of two paths:

- **The WebFetch tool** — works in Cowork and most sandboxes. Uses VirusTotal's v2 endpoints.
- **The bundled script** `scripts/netcheck.py` — runs every lookup at once where the shell has internet, such as a workstation. Uses the richer VirusTotal v3 API.

netcheck tries the script first when a shell exists, then falls back to WebFetch if the shell has no egress.

### API keys

netcheck reads optional keys from environment variables. Sources without a key degrade to their free tier or are skipped.

| Variable | Source |
|---|---|
| `VT_API_KEY` | VirusTotal |
| `SHODAN_API_KEY` | Shodan host API |
| `CERTSPOTTER_API_KEY` | Cert Spotter |

### Files

| Path | Purpose |
|---|---|
| `SKILL.md` | Workflow, scoring rules, and output format. |
| `scripts/netcheck.py` | Runs all lookups and prints one JSON object. |
| `references/sources.md` | Full endpoint catalog, auth details, and failure behavior. |

### Scope

netcheck is passive, defensive reconnaissance only. If you ask it to scan, exploit, or log in, it declines that part and explains that it is read-only.

## bugbounty_prompt

This prompt drives an authorized web security assessment against a bug bounty program, a vulnerability disclosure program (VDP), or a target the user asserts they own or hold written permission to test. It derives an engagement contract, maps the attack surface passively, runs manual and targeted vulnerability probes in a fixed order, and writes validated findings to an `engagement/` directory.

Every action is gated on authorization and scope. The run tests only what a policy or the user explicitly authorizes, uses manual low-rate probes, and stops at proof rather than exploitation.

### Inputs

The prompt takes one of two inputs:

- **Mode A — program policy.** `{{PROGRAM_URL}}`: a public policy page (HackerOne, Bugcrowd, Intigriti, a self-hosted VDP, or a `/.well-known/security.txt`). The run extracts rules of engagement, scope, and severity guidance from it.
- **Mode B — direct target.** `{{TARGET_URL}}`: a domain or URL plus the user's explicit statement that testing is authorized. The run records the authorization and treats the standing rules as the full rule set.

### Authorization and scope gate

Before any request reaches a target, the run derives an engagement contract in `engagement/CONTRACT.md`:

- In Mode A, it fetches the policy and records the operator, rules of engagement, in- and out-of-scope classes, severity guidance, and the snapshot date. If it cannot fetch the policy, it stops.
- In Mode B, it records the user's exact authorization statement and its basis. If authorization is ambiguous or absent, it asks once; if the user cannot assert it, it stops.

Each in-scope host is written to `engagement/scope.txt`, annotated `policy-listed`, `scope-page`, `user-authorized`, or `inferred`. Only the first three are tested directly; anything `inferred` needs a one-line user confirmation first. Recon-surfaced assets in third-party namespaces stay quarantined until a concrete ownership signal ties them to the target.

### Standing rules

These defaults apply unless a live policy or the user's constraints override them:

- Rate limit of three requests per second, with back-off on 429s or WAF escalation.
- Manual, targeted probes only — no automated scanning, DoS, brute forcing, password spraying, or social engineering.
- No data modification or destruction; access the minimum needed to prove a finding.
- Stop and report on any unauthorized access to sensitive data, accounts, or command execution.
- Log every request to `engagement/requests.log`; keep all work products under `engagement/`.
- On a confirmed block, slow down — never rotate IPs or infrastructure to evade it.

### Workflow

The run tracks progress in `engagement/STATE.md` and executes phases in order:

- **Recon (passive).** Certificate-transparency logs, Wayback and Common Crawl, public DNS, dangling-CNAME checks, org OSINT over public repos and SaaS workspaces, breach corpora, public CI/CD exposure, and ownership-gated cloud-asset probes — all against public APIs, filtered to scope.
- **Phase 1 — JS and route mining.** Local, zero-request analysis of JS bundles for API routes, DOM-XSS sinks, secrets, source maps, and historical endpoint diffs.
- **Phase 1.5 — Subdomain and HTTP enumeration.** Passive-first host discovery, HTTP fingerprinting, vhost cross-probes, and subdomain-takeover impact escalation.
- **Phase 2 — Unauthenticated testing.** Baseline-first probes for access control, injection (SQLi, SSRF, SSTI, XXE, command injection, LFI, NoSQL), XSS, CORS, open redirect, cache deception, and more — one targeted request per endpoint, judged by response delta.
- **Phase 2.5 — Framework-specific probes.** Fingerprint-gated checks for Next.js, Laravel, Spring Boot, ASP.NET, Jenkins, Kubernetes, gRPC, OData, and others.
- **Phase 3 — Authenticated testing.** Runs only if the user supplies two test accounts they own. Covers IDOR/BOLA, privilege escalation, stored XSS, mass assignment, CSRF, session and JWT handling, business logic, MFA bypass, and account-recovery flows.

### Validation discipline

Before writing anything up, the run applies an impact-only filter. Missing headers, stack traces, and version banners are context, never standalone findings. Access-control findings need cross-account proof; bypass claims need a response-body differential; timing claims need at least ten interleaved trials at 2σ. Any Critical or High is reproduced with two independent HTTP stacks, and severity is judged against the program's guidance rather than inflated.

### Output

All artifacts live under `engagement/`:

| Path | Contents |
|---|---|
| `CONTRACT.md` | Authorization, rules of engagement, scope sources, and snapshot date. |
| `scope.txt` | In-scope hosts, one per line, each annotated with its source. |
| `STATE.md` | Recon and phase checklist; prevents repeated work. |
| `requests.log` | One line per request: timestamp, host, method, path, status. |
| `findings/` | Request/response pairs supporting each finding. |
| `FINDINGS.md` | Summary table: host, endpoint, class, severity, evidence, reproduction. |

Evidence is sanitized — secrets stripped, victim PII redacted, HARs cleaned, test credentials rotated after submission. The run honors the program's or user's disclosure terms and securely deletes `engagement/` once reports are submitted.

### Scope and safety

This prompt is for authorized testing only. It refuses to proceed on unverified authorization, tests only confirmed-in-scope assets, and stops at the detection differential or out-of-band callback that proves a finding — it never iterates to extract data, escalates to a shell, or poisons other users' traffic.
