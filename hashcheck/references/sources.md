# hashcheck source catalog

Full reference for every source hashcheck uses: endpoints, authentication,
environment-variable names, the exact fields worth reading, and how each source
fails. Consult this when a lookup returns something unfamiliar, you need an
alternate source, or you're deciding which path to run.

## Contents

- [Which path, which keys](#which-path-which-keys)
- [VirusTotal](#virustotal)
- [MalwareBazaar (abuse.ch)](#malwarebazaar-abusech)
- [Hybrid Analysis](#hybrid-analysis)
- [Joe Sandbox](#joe-sandbox)
- [Web search](#web-search)
- [Failure behavior summary](#failure-behavior-summary)

## Which path, which keys

Two ways to reach the sources; pick by environment.

| Path | Works where | Reaches | Header support |
|---|---|---|---|
| `scripts/hashcheck.py` | shell has internet + env keys | all four APIs, deep fields | yes (`x-apikey`, `Auth-Key`, `api-key`, POST) |
| WebFetch + WebSearch | Cowork / sandboxes, shell has no egress | VirusTotal **v2** only + web search | no — GET only, key must ride in the URL |

Environment variables the script reads (all optional; a missing key skips that
source cleanly rather than erroring):

| Variable(s) | Source |
|---|---|
| `VT_API_KEY` | VirusTotal |
| `MB_API_KEY` or `ABUSE_CH_API_KEY` | MalwareBazaar / abuse.ch |
| `HYBRID_ANALYSIS_KEY` or `HA_API_KEY` | Hybrid Analysis |
| `JOE_SANDBOX_KEY` or `JBX_API_KEY` (+ optional `JOE_SANDBOX_URL`) | Joe Sandbox |

## VirusTotal

The strongest single source for a file hash. It aggregates ~70 AV engines and,
crucially, exposes the file's structure and signature — the data an analyst
otherwise needs the sample itself to see.

### v3 — the rich report (script path)

```
GET https://www.virustotal.com/api/v3/files/{hash}
Header: x-apikey: <VT_API_KEY>
```

`{hash}` may be MD5, SHA-1, or SHA-256. A **404** means the hash is unknown to
VirusTotal — a real finding (report it as "unknown to VT"), not an error. A
**401** means the key is invalid; a **429** means you hit the quota (the public
key allows ~4 lookups/minute, 500/day).

Read these from `data.attributes`:

| Field | Use |
|---|---|
| `last_analysis_stats` | `{malicious, suspicious, undetected, harmless, ...}` — the headline score. "malicious" is your numerator. |
| `last_analysis_results{}` | Per-engine `{category, result}`. Keep the `malicious`/`suspicious` ones; `result` is the family label. |
| `popular_threat_classification.suggested_threat_label` | VT's rolled-up family guess, e.g. `trojan.agenttesla/androm`. |
| `type_description`, `type_tag`, `size` | What the file is. |
| `meaningful_name`, `names[]` | Names it has been submitted under. A mismatch with the claimed name is a flag. |
| `first_submission_date`, `last_analysis_date` | Unix timestamps. Recency of first sight matters for campaign timing. |
| `reputation`, `total_votes` | Community signal; weak on its own. |
| `signature_info` | See below — code signing. |
| `pe_info` | See below — sections and entropy. |
| `sandbox_verdicts{}` | Per-sandbox `{category, malware_names, confidence}`. |
| `crowdsourced_yara_results[]` | Named YARA rules that matched; often carry a precise family. |
| `sigma_analysis_results[]` | Suspicious-behavior log rules, with `rule_level`. |

**`signature_info`** (PE and Mach-O). Useful keys: `verified` (the
plain-English status string), `subject`, `signers`, `product`, `description`,
`signing date`, `counter signers`, `original name`. Judge the signer identity and
the verification status, not merely the presence of a signature. "Invalid",
"revoked", or a signer that doesn't match the claimed publisher is worse than
unsigned.

**`pe_info`** (Windows PE). Useful keys: `imphash` (import-table fingerprint),
`entry_point`, `import_list[].library_name`, and `sections[]` — each with
`name`, `entropy` (0–8), `raw_size`, `virtual_size`. Entropy above ~7.2 flags
packing/encryption. Telltale names (`UPX0`, `.themida`, `.vmp0`) name the packer.

### v2 — the verdict-only fallback (WebFetch path)

```
GET https://www.virustotal.com/vtapi/v2/file/report?apikey=<VT_API_KEY>&resource=<hash>
```

The key rides in the query string, so WebFetch can call this. Returns
`response_code` (`1` = seen, `0` = never scanned), `positives`, `total`,
`scan_date`, `sha256`, and `scans{}` (per-engine `{detected, result}`). No
`pe_info`, no `signature_info` — say so rather than inventing section/entropy
detail on this path.

## MalwareBazaar (abuse.ch)

A corpus of confirmed malware samples. Best for confirmed-bad files: family
name, code-signing certificate details, fuzzy hashes, and how the sample is
delivered. It only knows *malware* — a "not found" here says nothing about a
benign file's safety.

```
POST https://mb-api.abuse.ch/api/v1/
Header: Auth-Key: <MB_API_KEY>
Body (form): query=get_info&hash=<hash>
```

An `Auth-Key` is required (free from https://auth.abuse.ch/). Without it the API
returns a `query_status` such as `unauthenticated` — the script reports that as a
skip. The POST + custom header means **WebFetch cannot call this**; it is a
script-path source.

Read `data[0]`:

| Field | Use |
|---|---|
| `query_status` | `ok`, `hash_not_found`, `illegal_hash`. |
| `signature` | Malware family, e.g. `AgentTesla`. The headline for MB. |
| `file_type`, `file_name`, `file_size` | File identity. |
| `first_seen` | When MB first saw it. |
| `imphash`, `tlsh`, `ssdeep` | Fingerprints for pivoting to related samples. |
| `tags[]` | Campaign/family/tooling tags. |
| `delivery_method` | e.g. `email_attachment`, `web_download`. |
| `code_sign[]` | Certificate `{subject_cn, issuer_cn, valid_from, valid_to, thumbprint}`. Abused/stolen certs show here. |
| `vendor_intel{}` | Keys name third-party sources (ANY.RUN, Triage, etc.) that have reports. |

## Hybrid Analysis

Falcon Sandbox. Best for dynamic behavior when the static picture is ambiguous.

```
GET https://www.hybrid-analysis.com/api/v2/search/hash?hash=<hash>
Headers: api-key: <key>   User-Agent: Falcon Sandbox   accept: application/json
```

(The old `POST /search/hash` is deprecated in favor of this GET form.) Custom
`api-key` header → **script-path only**. Returns an array of reports; read from
each:

| Field | Use |
|---|---|
| `verdict` | `malicious`, `suspicious`, `no specific threat`, `whitelisted`. |
| `threat_score`, `threat_level` | 0–100 score and level. |
| `av_detect` | AV detection percentage from their scan. |
| `vx_family` | Family label. |
| `environment_description` | Which sandbox image ran it. |
| `mitre_attcks[].technique` | Observed ATT&CK techniques — the "what it does". |

A restricted (free, non-vetted) key can still search by hash. A **403** usually
means the key's authorization level is too low for that field/endpoint.

## Joe Sandbox

Joe Sandbox Cloud. A second dynamic opinion and score. Two steps: search for the
hash, then pull the analysis info.

```
POST {JOE_SANDBOX_URL or https://jbxcloud.joesecurity.org/api}/v2/analysis/search
Body (form): apikey=<key>&q=<hash>
        -> data[].webid

POST .../v2/analysis/info
Body (form): apikey=<key>&webid=<webid>
        -> data.detection, data.score, data.threatname
```

Form-param auth + POST → **script-path only**. `detection` is one of `clean`,
`suspicious`, `malicious`, `unknown`; `score` is 0–100. No hits means Joe Sandbox
has no cloud analysis for that hash — not a safety signal by itself.

## Web search

The universal fallback and corroborator; the only reputation source that always
works on the WebFetch path. Query the raw hash, optionally with `malware`,
`abuse`, or a suspected family name:

```
"44d88612fea8a8f36de82e1278abb02f" malware
```

Surfaces vendor writeups, sandbox report pages, blocklist entries, and threat
reports. Treat a hash merely *listed* in an indicator table as corroboration,
not as independent analysis — prefer engine detections, signing facts, and
sandbox verdicts over raw hit counts. When no API keys are set, this plus the
VT v2 check is your whole investigation; say so in the report.

## Failure behavior summary

| Symptom | Meaning | Do |
|---|---|---|
| VT 404 / `found: false` | hash unknown to VirusTotal | report as Unknown-to-VT; lean on other sources |
| VT 401 | bad `VT_API_KEY` | note key invalid; fall back to web search |
| VT 429 | quota exhausted (public key ~4/min) | wait or note the gap; don't hammer |
| MB `hash_not_found` | not in the malware corpus | says nothing about a benign file |
| MB `unauthenticated` | no/invalid `Auth-Key` | note the skip; set `MB_API_KEY` |
| HA 403 | key authorization level too low | note the gap |
| every source: connection error | shell has no egress | switch to WebFetch + WebSearch path |

Absence of evidence is not evidence of safety. Write "no negative reputation
found across <the sources you reached>" and name them, rather than "clean".