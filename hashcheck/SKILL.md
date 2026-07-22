---
name: hashcheck
description: >-
  Run an open-source intelligence (OSINT) investigation on a single file hash
  (MD5, SHA-1, or SHA-256) and return a malware analyst's briefing: a risk
  verdict, a short technical summary, and a facts table. Weighs multi-engine
  detections, code-signing status, and file structure (PE sections, entropy)
  heavily. Use this whenever the user types "hashcheck" followed by a hash, and
  also whenever they paste a hash or point at a file and ask you to
  "investigate", "look up", "check the reputation of", "analyze", "run OSINT
  on", "is this file safe", "is this malware", "what is this file", or "should I
  trust this binary" — even if they don't say the word "hashcheck". Trigger on
  bare hashes like 44d88612fea8a8f36de82e1278abb02f, on a file the user uploads
  or names, and on requests to triage a suspicious download, attachment, or
  sample. This is passive, defensive reconnaissance only.
---
 
# hashcheck
 
Investigate one file — identified by its hash — and give a malware analyst a
briefing they can act on in under a minute. If the user gives you a file instead
of a hash, compute its SHA-256 first (see "Accept files and batches"). A verdict
of benign, suspicious, or malicious is the point; get there and justify it.
 
Don't dump raw API output. Synthesize. Pull detections, code-signing, file
structure, and sandbox behavior into one picture, then make a defensible call
about how much to worry.
 
This is **passive reconnaissance**. You look up what public malware databases
already know about a hash. You never detonate the sample, download and run it,
submit it anywhere without saying so, or reach out to attacker infrastructure.
The hash is a fingerprint; treat this as a records check on that fingerprint. If
a user asks hashcheck to execute or actively probe a sample, decline that part
and explain that hashcheck is read-only.
 
## What the verdict rests on
 
A hash lookup answers four questions. Weight them in this order.
 
1. **Consensus detection.** How many reputable engines flag this file, and what
   do they call it? A high, consistent detection count with an agreed family
   name (e.g. "Emotet", "AgentTesla") is the strongest single signal. A handful
   of generic "heuristic" or "ML" hits on an otherwise clean file is weak.
2. **Code-signing and provenance.** A file signed by a named, reputable vendor
   with a currently-valid certificate that VirusTotal verifies is far more
   trustworthy than an unsigned one. A *broken*, *expired*, *revoked*, or
   *mismatched* signature is worse than no signature at all, because it signals
   tampering or impersonation. Read who signed it, not just whether it is signed.
3. **File structure.** For Windows PE files, section entropy and layout betray
   packing and obfuscation. A section with entropy above ~7.2 is likely packed
   or encrypted — common in malware, but also in legitimate installers, so it is
   a flag, not a conviction. An unusual section name (`.UPX0`, `.themida`), a
   tiny import table, or a mismatch between the file type and its extension all
   deserve a mention.
4. **Sandbox behavior and corroboration.** Dynamic-analysis verdicts, dropped
   files, network indicators, and YARA/Sigma matches turn "some engines flag it"
   into "here is what it does." Reach for these when the static picture is
   ambiguous or the user is working an active incident.
Absence of evidence is not evidence of safety. A hash no database has seen is
**unknown**, not clean — say so, and lean on structure and signing to reason
about it.
 
## Network access: pick the working path first
 
hashcheck depends on reaching public malware-intel APIs. How you reach them
varies by environment, and choosing wrong produces a page of connection errors
instead of a report.
 
1. **The bundled script** `scripts/hashcheck.py`. This runs every lookup at once
   and prints a single compact JSON object. It works where the **shell has
   internet and the API keys are set as environment variables**, such as Claude
   Code on a workstation. It queries the richer, authenticated endpoints —
   VirusTotal **v3** (`pe_info`, `signature_info`, sandbox verdicts),
   MalwareBazaar, Hybrid Analysis, and Joe Sandbox — that need custom headers
   the WebFetch tool cannot send. Prefer this path whenever a shell with egress
   exists: `python3 scripts/hashcheck.py <hash-or-file>`.
2. **The WebFetch tool** (`mcp__workspace__web_fetch` or `WebFetch`) plus
   `WebSearch`. Use this in Cowork and other sandboxes where the shell has no
   outbound internet. WebFetch can only issue GET requests and cannot set the
   `Auth-Key`, `x-apikey`, or `api-key` headers the deep endpoints require, so on
   this path you get **VirusTotal's v2 endpoint** (which accepts the key as a
   query parameter) for the multi-engine verdict, plus `WebSearch` for
   corroboration. You will usually not get PE sections, entropy, or signing
   detail on this path — say so in the report rather than inventing it.
Try the script first when a shell exists. If its output contains
`Tunnel connection failed`, `network unreachable`, `name resolution`, or every
source reports a connection error, the shell has no egress — switch to the
WebFetch path and don't retry the script.
 
Every source degrades independently. A dead, rate-limited, or key-less source is
a gap you report, not a reason to stop. Collect what you can, then state what you
missed and why. The verdict must reflect the evidence you actually gathered.
 
## Accept files, hashes, and batches
 
**A bare hash** is the common case. Normalize it: strip whitespace and any
`sha256:` / `0x` prefix, lowercase the hex. Classify by length — 32 hex chars is
MD5, 40 is SHA-1, 64 is SHA-256. All three are valid lookup keys; SHA-256 is
preferred because it is collision-resistant and every source keys on it. If the
string is not valid hex of one of those lengths, say so instead of guessing.
 
**A file** — uploaded or named by path — means the user wants you to identify
what they have. Compute all three digests before looking anything up; the script
does this automatically when handed a path, or run
`python3 scripts/hashcheck.py /path/to/file`. Report the SHA-256 you computed so
the user can confirm it matches their file. Never execute the file to inspect it.
 
**Multiple hashes** in one request means triage a set. Run each through the same
workflow, but keep each write-up tight — lead with a one-line summary table
(hash, verdict, family) so the analyst can scan the batch, then give the full
briefing only for the ones that warrant it. Don't produce five identical
full-length reports for five clean files.
 
## Workflow
 
### 1. Identify the file
 
From the sources, establish what the file *is* before judging it: file type and
"magic" (PE, ELF, Mach-O, PDF, Office, script, archive), size, common names it
has been seen under, and first-seen date. VirusTotal's `type_description`,
`meaningful_name`, `names[]`, `size`, and `first_submission_date` cover this;
MalwareBazaar's `file_type`, `file_name`, and `first_seen` corroborate. A recent
first-seen date on a file already carrying detections suggests a fresh campaign.
 
### 2. Read the detection consensus
 
This is the headline. From VirusTotal, read `last_analysis_stats`
(`malicious` / `suspicious` / `undetected` / `harmless`) for the score, and
`last_analysis_results{}` for *what* engines call it. Name two or three reputable
engines (Microsoft, Kaspersky, ESET-NOD32, Malwarebytes) and the family they
assign rather than listing all ~70. `popular_threat_classification.suggested_
threat_label` gives VirusTotal's rolled-up family guess — quote it when present.
 
On the WebFetch path, the v2 `file/report` endpoint gives `positives`/`total`
and per-engine `scans{}` instead; read the same signal from those.
 
Interpret honestly. Ten engines agreeing on "Trojan:Win32/Wacatac" is a
conviction. Two engines with generic "ML.Attribute.HighConfidence" or
"gen:variant" labels on a file nothing else flags is a lead to verify, not a
verdict. Say which situation you are in.
 
### 3. Check code-signing and provenance
 
Pull the digital signature. VirusTotal `signature_info` carries `verified`
(the plain-English status — "Signed", "Invalid signature", "This file is not
signed"), `subject` / `signers` (who signed it), `product` and `description`,
and the signing/counter-signing dates. MalwareBazaar's `code_sign[]` gives the
certificate `subject_cn`, `issuer_cn`, `valid_from` / `valid_to`, and
`thumbprint`.
 
Judge four things and say what each means:
 
- **Signed vs. unsigned.** Unsigned is normal for scripts and open-source
  tools, unremarkable on its own, but removes a trust anchor for a Windows
  binary that would normally ship signed.
- **Verification status.** "Signed" and verified is reassuring. "Invalid",
  "expired", "revoked", or "unverifiable" is a red flag — a tampered or spoofed
  signature is worse than none, because it is an attempt to borrow trust.
- **Who signed it.** A signer that matches the software's claimed publisher
  (Microsoft, Google, a known vendor) supports legitimacy. A signer that is a
  random company, a mismatched name, or a recently-issued certificate on a
  suspicious file is a strong negative — stolen and abused code-signing
  certificates are a known attacker technique.
- **Certificate age and validity window.** A certificate issued days before the
  file first appeared, or one already expired at signing time, deserves scrutiny.
### 4. Examine file structure (PE sections and entropy)
 
For Windows PE files, read VirusTotal `pe_info`: `sections[]` (each with `name`,
`virtual_address`, `raw_size`, and `entropy`), `imphash`, `import_list[]`
(the DLLs and APIs it pulls in), `entry_point`, and any `resource_details`.
 
What to look for and why:
 
- **High section entropy** (above ~7.2 on a 0–8 scale) means the section is
  compressed or encrypted. Packers (UPX, Themida, ASPack) and malware droppers
  do this to hide code from static scanners. Legitimate installers pack too, so
  treat high entropy as a flag that raises the bar for a "benign" call, not as
  proof of malice.
- **Telltale section names** — `UPX0`/`UPX1`, `.themida`, `.aspack`, `.vmp0`,
  or random-looking names — name the packer outright.
- **A minimal import table** (a handful of APIs, often just `LoadLibrary` /
  `GetProcAddress`) is classic for a packed stub that unpacks the real payload at
  runtime. A rich, coherent import set is more consistent with normal software.
- **Type/extension mismatch** — a file served as `invoice.pdf` whose magic says
  PE executable — is itself a finding worth leading with.
On the WebFetch path you will usually not have `pe_info`. Note that section and
entropy analysis was unavailable rather than omitting the topic silently.
 
### 5. Pull sandbox behavior and corroboration
 
When static signals are ambiguous or the user is investigating an active
incident, add dynamic and community evidence:
 
- **Hybrid Analysis** (`/api/v2/search/hash`) returns `verdict`,
  `threat_score`, `vx_family`, and `mitre_attcks[]` — behavior mapped to the
  MITRE ATT&CK framework (a catalog of adversary techniques). Read the verdict
  and the top techniques.
- **Joe Sandbox** search returns analyses with a maliciousness score and
  detection; report the score and whether it flagged the sample.
- **VirusTotal** `sandbox_verdicts{}`, `crowdsourced_yara_results[]` (named
  detection rules that matched — often carry a precise family), and
  `sigma_analysis_results[]` (suspicious-behavior log rules) add behavioral
  weight without a separate sandbox call.
- **MalwareBazaar** `vendor_intel{}`, `tags[]`, and `delivery_method` tell you
  how the sample is distributed (spam attachment, drive-by, etc.).
- **`WebSearch`** the raw hash, e.g. `"44d88612fea8a8f36de82e1278abb02f"
  malware`, to surface vendor writeups, sandbox reports, and blocklist entries.
  Rely on it entirely when no API keys are set.
Distinguish **what the file is** from **what merely mentions it**. A blog that
lists a hash in a table of indicators is corroboration; it is not independent
analysis. Prefer engine detections, signing facts, and sandbox verdicts over
raw search-hit counts.
 
## Write the summary in Google technical writing style
 
The summary is the part an analyst actually reads. Follow Google's technical
writing standards, because they produce prose a reader scans quickly and cannot
misread:
 
- **State the conclusion first.** Open with what the file is and the risk call.
  Don't build to it.
- **Use active voice and present tense.** Write "Microsoft flags this as
  Wacatac," not "this is flagged as Wacatac by Microsoft."
- **Keep sentences short.** One idea per sentence. Aim under 25 words.
- **Address the reader as "you."** Write "quarantine this on your endpoints,"
  not "one might consider quarantining it."
- **Define terms and expand abbreviations on first use.** Write "imphash (import
  hash, a fingerprint of the file's import table)."
- **Cut filler.** Delete "basically," "very," "it should be noted that," and "in
  order to." Replace vague words with specific ones.
- **Avoid ambiguous pronouns.** Write "this certificate," not "this."
- **Never hedge to sound safe.** If the data is thin, say which data is missing.
Hold the summary to **one paragraph of three to five sentences**. Be technical
and concrete: name the family, the engine count, the signer, the packer, the
entropy. Prefer a specific fact over an adjective. An analyst triaging a queue
reads the verdict and the summary; everything else is reference. If a sentence
doesn't change what the reader does next, cut it.
 
**Before (verbose, passive, hedged):**
> It should be noted that this file appears to possibly be detected by a number
> of different antivirus engines, and it seems that it may have been packed using
> some kind of packing software, which is often associated with malware.
 
**After (Google style):**
> This is AgentTesla, an info-stealer. 58 of 72 engines flag it, with Microsoft,
> ESET, and Kaspersky agreeing on the family. The file is an unsigned Windows PE
> packed with UPX (its `.UPX1` section reads 7.9 entropy) and imports only
> `LoadLibrary`/`GetProcAddress` — a classic unpack-at-runtime stub. Quarantine
> it and hunt for the `%AppData%` drop it creates.
 
## Output format
 
Produce these parts in this order. Lead with the verdict, because an analyst
reads top-down and wants the conclusion first.
 
```
## hashcheck: <sha256 or the hash given>  —  Verdict: <Benign | Suspicious | Malicious | Unknown>
 
<Three to five sentences in Google technical writing style. What the file is,
its detection consensus, its signing and structure, and why you assigned that
verdict.>
 
### Facts
| Field | Value |
|---|---|
| Hash (query) | <the hash the user gave, with its type> |
| SHA-256 | |
| SHA-1 | |
| MD5 | |
| File type | <PE32 exe, ELF, PDF, Office macro, script, ...> |
| File size | |
| Common names | <names it has been seen under> |
| First seen | <date> |
| Detections | <e.g. 58/72 malicious; or "0/70"; or "not in any database"> |
| Threat label | <VT suggested_threat_label / agreed family> |
| Notable engines | <2–3 reputable engines and what they call it> |
| Signature | <Signed by <signer>, verified; or Unsigned; or Invalid/Expired/Revoked> |
| Signing cert | <issuer, validity window; omit if unsigned> |
| Packing / entropy | <packer name and/or high-entropy sections, or "no packing indicators"> |
| Imphash | |
| Sandbox verdict | <Hybrid Analysis / Joe Sandbox score and behavior, or "not reached"> |
| YARA / Sigma | <named rule matches, or omit> |
| MITRE ATT&CK | <top techniques observed, or omit> |
| Distribution | <delivery method / tags, or omit> |
| Sources reached | <list; name any that failed or lacked a key> |
 
### Notes
<Up to five short bullets. Caveats, gaps, or leads worth a human's follow-up.
Omit this section if there are none.>
```
 
Include a row only when you have a value or a meaningful "not reached" for it.
Keep a row when its emptiness is informative, such as "Detections: not in any
database (file unknown to all sources)." Drop signing/PE rows entirely for file
types where they don't apply (a PDF has no `pe_info`; a shell script has no
signature).
 
Keep Notes to five bullets at most, and put only decision-relevant material
there — a caveat that changes how to read a fact, a gap that limits confidence,
or a lead worth chasing. Notes are not a place to restate the table or narrate
your process.
 
For a **batch**, print a one-line summary table first:
 
```
| Hash (short) | Verdict | Family / note |
|---|---|---|
| 44d88612… | Malicious | AgentTesla, 58/72 |
| a1b2c3d4… | Benign | Signed Microsoft, 0/72 |
```
 
Then give the full briefing only for hashes that are Suspicious, Malicious, or
that the user should look at closely.
 
## Assign the verdict
 
The verdict is a judgment call, not a formula. Explain your reasoning in the
summary so a human can disagree. **Use exactly one of `Benign`, `Suspicious`,
`Malicious`, or `Unknown` in the header.** Don't qualify it, hyphenate it, or
invent a compound label — downstream readers and tooling key off that single
word.
 
- **`Malicious`** — a meaningful count of reputable engines agree it is
  malware, especially with a consistent family name; or a sandbox reports
  malicious behavior; or the file combines strong structural red flags (packing,
  a spoofed or revoked signature, type/extension mismatch) with any detections.
- **`Suspicious`** — the picture is mixed or concerning but not conclusive: a
  few detections without consensus, heavy packing or high entropy on an unsigned
  binary with no clean provenance, a broken or mismatched signature, or a file
  that behaves oddly in a sandbox but engines haven't caught up. Also use this
  when data is partial enough to leave real doubt — "Suspicious — limited data"
  tells the analyst to look closer.
- **`Benign`** — zero or only trivial generic detections, and where applicable a
  valid signature from a named reputable vendor and an unremarkable structure.
  A widely-seen, long-known file with clean results across sources earns this.
  Say "no negative reputation found across <sources>," not "clean," and name the
  sources.
- **`Unknown`** — no source has a record of the hash and you can't compute
  structure (e.g. you have only the hash, not the file). This is common and
  honest. Don't upgrade it to Benign; an unseen file is unproven, not safe.
  Tell the user that submitting the file itself (which hashcheck won't do
  automatically) would resolve it.
A clean, signed file can still do something the user should think twice about —
a legitimate remote-access tool, say. The verdict rates **the file's
maliciousness**; if there's a separate "legitimate but risky" angle, put it in
the summary's last sentence or the first Note and keep the header word clean.
 
When data is thin, don't overclaim. State what would change your assessment —
"if you can share the file, submitting it to VirusTotal would confirm."
 
## Reference
 
Read `references/sources.md` for the full endpoint catalog, authentication
details, exact response fields, environment-variable names, and per-source
failure behavior. Consult it when a lookup returns something unfamiliar, you need
an alternate source, or you're wiring up which keys are present.