# Claude Skills
A small collection of Claude and Claude Code skills for aiding cybersecurity analysis work. Skills are designed for Claude Code but will fallback to other methods and work with Claude Desktop as well but without as much information 

[netcheck](#netcheck) investigates a single IP address or domain and returns a security analyst's briefing — a risk verdict (Low, Medium, or High), a one-paragraph summary, and a facts table. It pulls together ownership provenance, DNS records, hosting and ASN, exposed services and CVEs, TLS certificate history, and reputation data into one picture, weighting registration age and ownership changes most heavily. It's passive reconnaissance only: it reads what public databases already know and never scans, exploits, or logs into a target.

[hashcheck](#hashcheck) does the same for a single file, identified by its hash (MD5, SHA-1, or SHA-256) — returning a malware analyst's briefing with a verdict (Benign, Suspicious, Malicious, or Unknown), a summary, and a facts table. It weighs multi-engine detection consensus, code-signing status, file structure like PE section entropy and packing, and sandbox behavior. Like netcheck, it's read-only: a records check on the fingerprint that never detonates or runs the sample.

Both follow the same design — try a bundled script when the shell has internet, fall back to WebFetch in sandboxes, degrade gracefully when a source is unavailable, and write the summary in Google technical writing style (conclusion first, active voice, short sentences).


# Skills
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

## Scope

netcheck is passive, defensive reconnaissance only. If you ask it to scan, exploit, or log in, it declines that part and explains that it is read-only.
