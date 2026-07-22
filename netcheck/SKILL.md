---
name: netcheck
description: >-
  Run an open-source intelligence (OSINT) investigation on a single IP address
  or domain and return a security analyst's briefing: a risk verdict, a short
  technical summary, and a facts table. Weighs ownership provenance heavily —
  registration age, recent registrar or registrant changes, and registrar
  reputation. Use this whenever the user types "netcheck" followed by an IP or
  domain, and also whenever they ask you to "investigate", "look up", "check
  the reputation of", "profile", "run OSINT on", "who owns", "who is behind",
  or "is this safe" for any IP address, domain, hostname, or URL — even if they
  don't say the word "netcheck". Trigger on indicators like 8.8.8.8,
  185.220.101.1, evil-domain.com, or a pasted URL. This is passive, defensive
  reconnaissance only.
---

# netcheck

Investigate one indicator — an IP address or a domain — and give a security
analyst a briefing they can act on in under a minute. A pasted URL is fine;
reduce it to its host.

Don't dump raw API output. Synthesize. Pull ownership, DNS, hosting, exposed
services, and reputation into one picture, then make a defensible call about how
much to worry.

This is **passive reconnaissance**. You look up what public databases already
know. You never scan, exploit, brute-force, log in, or send payloads to the
target. If a user asks netcheck to do any of those, decline that part and
explain that netcheck is read-only.

## Network access: pick the working path first

netcheck depends on reaching public APIs. How you reach them varies by
environment, and choosing wrong produces a page of connection errors instead of
a report.

1. **The WebFetch tool** (`mcp__workspace__web_fetch` or `WebFetch`). This path
   works in Cowork and most sandboxes, where the shell has no outbound
   internet. Call each JSON endpoint below and read the JSON from the result.

2. **The bundled script** `scripts/netcheck.py`. This script runs every lookup
   at once and prints a single JSON object. It works only where the **shell
   has internet**, such as Claude Code on a workstation. It queries the richer
   VirusTotal v3 API, which needs an `x-apikey` header.

Both paths reach every source, including VirusTotal and Shodan. The WebFetch
path uses VirusTotal's v2 endpoints, which accept the key as a query parameter.

Try the script first when a shell exists: `python3 scripts/netcheck.py <target>`.
If the output contains `Tunnel connection failed`, `403 Forbidden`,
`network unreachable`, or `name resolution` errors, the shell has no egress.
Switch to the WebFetch tool and don't retry the script.

Every source degrades independently. A dead or rate-limited source is a gap you
report, not a reason to stop. Collect what you can, then state what you missed.

## Workflow

### 1. Normalize and classify the target

Strip the scheme and path, so `https://sketchy.example.com/login?x=1` becomes
`sketchy.example.com`. Determine whether the target is an IP address or a
domain. For a domain, resolve it to an IP early, because the hosting and
exposed-service lookups need one.

### 2. Establish ownership provenance

Do this step first for domains, and weight it heavily. Ownership history
separates a legitimate business from a disposable attack domain more reliably
than any other single signal. Most malicious domains are young, and a sudden
registrar or registrant change on an old domain can indicate a hijack.

```
https://api.whois.vu/?q=<domain>
```

The response is JSON. Read these fields:

| Field | Meaning |
|---|---|
| `created` | Registration date, as a Unix timestamp. Convert it and compute the age. |
| `updated` | Last record change, as a Unix timestamp. This is your change-detection signal. |
| `expires` | Expiry date. A far-future expiry suggests long-term investment. |
| `registrar` | The sponsoring registrar. |
| `statuses` | EPP status codes. `clientTransferProhibited` and similar locks indicate deliberate anti-hijacking configuration. |
| `whois` | Full WHOIS text. Read `Registrant Organization` and `Registrant Country` from it. |

Assess four things, and say what each one means in the summary:

- **Registration age.** Under 30 days is a strong suspicion signal; attackers
  register domains shortly before use. 30 to 180 days is elevated. Multiple
  years with a stable record is reassuring.
- **Recency of change.** Compare `updated` against `created` and today. A record
  changed in the last 30 to 90 days deserves scrutiny, especially on an
  otherwise old domain, because it can indicate a transfer, a hijack, or a
  resale to a new operator. A change that coincides with the suspicious activity
  the analyst is investigating is a significant finding.
- **Registrar reputation.** Corporate brand-protection registrars such as
  MarkMonitor or CSC signal an organization that invests in domain security.
  Bulk, low-cost, or crypto-only registrars with weak abuse handling appear
  disproportionately in abuse data. Judge the registrar's abuse-handling
  reputation rather than its price, and use `WebSearch` if you don't recognize
  it.
- **Registrant identity.** A named organization that matches the site's claimed
  operator supports legitimacy. Privacy or proxy registration is common and
  legitimate on its own, but it removes attribution — treat it as risk-relevant
  only when combined with youth, a recent change, or other negative signals.

For an IP address, the equivalent of registration history is the **network
allocation**. Apply the same age and change reasoning to it:

```
https://stat.ripe.net/data/whois/data.json?resource=<ip>
```

RIPEstat covers every regional registry and returns clean JSON. Read
`data.records[]`, which is a list of key/value pairs. The useful keys are
`inetnum` (the assigned range), `netname`, `country`, `org`, `status`, `mnt-by`
(the maintainer, which often names the real operator), `created` (when the
allocation was assigned), and `last-modified` (when it last changed). Read
`data.irr_records[]` for the announcing `origin` AS number.

Treat `created` and `last-modified` exactly as you treat a domain's `created`
and `updated`. A range assigned last month, or re-assigned to a new
organization recently, deserves the same suspicion as a young domain.

For addresses in North America, `https://whois.arin.net/rest/ip/<ip>.txt`
returns plain text that the WebFetch tool renders correctly. Outside the ARIN
region it returns only a delegation stub — if you see `NetType: Allocated to
RIPE NCC` or a `NetName` like `RIPE-185`, that is not the real owner, so use
RIPEstat instead. Note also that ARIN's `RegDate` reflects the registry record,
not necessarily when the operator first controlled the block.

Avoid `https://rdap.org/ip/<ip>` on the WebFetch path. RDAP returns
`application/rdap+json`, which the tool usually renders as `[binary data]`. The
bundled script decodes it correctly.

### 3. Resolve DNS

For a domain, pull `A`, `AAAA`, `MX`, `NS`, `TXT`, and `SOA` records. These
records show where the domain points, who handles its mail, whose nameservers it
trusts, and which services have verified it.

Use DNS over HTTPS, which works even where UDP port 53 is blocked:

```
https://dns.google/resolve?name=<domain>&type=<A|AAAA|MX|NS|TXT|SOA>
```

Read the answers from `Answer[].data`. `Status: 0` means success. `Status: 3`
means the name doesn't exist, which is itself a finding. Take the first `A`
record as the resolved IP.

For an IP target, do a reverse lookup with
`https://dns.google/resolve?name=<reversed-ip>.in-addr.arpa&type=PTR`, or read
the hostnames that Shodan returns in step 5.

### 4. Identify hosting, geolocation, and ASN

Determine where the target runs and who operates the network. Hosting on a
residential ISP, a bulletproof host, or a Tor-associated network reads
differently from AWS or Cloudflare.

```
https://ipwho.is/<ip>
```

Read `country`, `city`, `connection.isp`, `connection.org`, and
`connection.asn`.

**Weigh the hosting type deliberately — it is a provenance signal, not just a
location.** Group what you find into three tiers:

- **Established cloud and CDN** — AWS, GCP, Azure, Cloudflare, Fastly, Akamai.
  Ubiquitous and mostly benign. On their own these lower suspicion slightly, but
  remember attackers rent them too, so they don't clear an indicator by
  themselves.
- **Commodity VPS and low-cost hosting** — providers that rent a bare virtual
  server by the hour with little identity verification. This tier deserves more
  suspicion than it often gets, because it is the default staging ground for both
  commodity crews and targeted intruders: cheap, anonymous, disposable, and
  quick to stand up. A **VPS** (virtual private server — a rented slice of a
  physical machine) hosting something that presents itself as a real company,
  bank, or webmail portal is a mismatch worth flagging. When `ipwho.is`
  `connection.org` names a budget VPS provider, or `ip-api`'s `hosting` field is
  `true` and no recognizable brand owns the range, treat the host as datacenter
  infrastructure standing in for a service that a legitimate operator would run
  on managed, attributable hosting. Weight it toward Medium and look harder at
  provenance and the certificate.
- **Bulletproof, residential-proxy, and Tor-associated networks** — the highest
  tier of concern. A bulletproof host that ignores abuse complaints, or a service
  fronted through residential-proxy space, points strongly at deliberate
  evasion.

Judge the operator, not just the geography. Use `WebSearch` on the ASN or the
`connection.org` name when you don't recognize it — a provider's abuse
reputation is a matter of public record.

### 5. Enumerate exposed services and known CVEs

Determine what listens on the host and whether any of it is known-vulnerable.

Free, no key — always try this first:

```
https://internetdb.shodan.io/<ip>
```

Read `ports`, `vulns` (CVE identifiers), `tags`, and `hostnames`. A populated
`vulns` array raises risk immediately.

InternetDB is small and answers the main question — what's open and is it
vulnerable. Prefer it, and escalate only when you need more.

With a Shodan key, for banners, software versions, and TLS certificates:

```
https://api.shodan.io/shodan/host/<ip>?key=<SHODAN_API_KEY>
```

Shodan takes its key as a query parameter, so this works through the WebFetch
tool. Be aware that this response is also expensive: it embeds full PEM
certificate chains and raw HTML page bodies for every service. Reach for it when
you need software versions, certificate details, or service banners that
InternetDB doesn't carry — not as a reflex. Read `ports`, `vulns`, `tags`,
`data[].product`, `data[].version`, and `data[].ssl.cert` (issuer, expiry,
subject alternative names). Skip the `chain` PEM blocks and `html` fields
entirely. A 404 means Shodan has no record of the host; a 401 means the key is
invalid.

### 6. Evaluate the TLS certificate and its history

A domain's certificate history is provenance you can't fake cheaply. Certificate
Transparency (CT) logs record every publicly-trusted certificate ever issued for
a name, with dates, so they tell you when a domain first started serving HTTPS
and how its certificate posture has changed.

CT sources are unusually flaky — crt.sh is famous for timing out or returning an
empty body under load, and on a restricted network or fetch allowlist a given CT
host may be unreachable entirely. So treat this as a cascade: try a source, and
the moment it comes back empty or errors, move to the next rather than retrying.
Don't leave the certificate assessment blank just because the first source
failed.

1. **crt.sh (primary CT log search).**
   ```
   https://crt.sh/?q=<domain>&output=json
   ```
   A JSON array, one object per logged certificate. Read `issuer_name`,
   `common_name`, `name_value` (covered names, newline-separated — this
   enumerates subdomains), `not_before` (when the cert became valid), and
   `not_after` (expiry). Sort by `not_before` for the timeline. An empty body or
   non-JSON response means crt.sh is unavailable right now — go to step 2.

2. **Cert Spotter (alternate CT source).** SSLMate's Cert Spotter covers the
   same logs and is up when crt.sh is down.
   ```
   https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names&expand=issuer&expand=not_before&expand=not_after
   ```
   A JSON array of issuance objects. Read `dns_names` (subdomain enumeration),
   `issuer.name` (the CA), and `not_before` / `not_after` (ISO dates — no
   timestamp conversion needed). The keyless tier is rate-limited and its
   unauthenticated results can be partial; the bundled script sends a
   `CERTSPOTTER_API_KEY` when one is set. An empty or `429` response means go to
   step 3.

3. **The served certificate (fallback when no CT source answers).** If both CT
   sources are unreachable — common on a locked-down fetch allowlist — you can
   still assess the certificate the host actually presents. Pull it from Shodan's
   `data[].ssl.cert` (issuer, subject, `subjectAltName`, expiry) via the Shodan
   host API, or, in a shell with egress, `openssl s_client -connect <host>:443
   -servername <host>`. You lose the issuance *timeline* — so you can't establish
   first-issuance age this way — but you still get issuer, subject, SANs, and
   whether the cert is self-signed or mismatched. Say plainly in the report that
   CT history was unavailable and note which fallback you used.

Whatever source answers, assess four things and say what each means:

- **First-issuance age.** The earliest `not_before` is roughly when the domain
  first stood up TLS. A domain whose *entire* certificate history began days or
  weeks ago is freshly built, even if WHOIS somehow reads older — attackers and
  targeted intruders stand up certificates the moment they deploy. Cross-check
  this against the WHOIS `created` date: a years-old registration whose *first
  ever* certificate appeared last week is a staging or repurposing signal, not a
  mature service.
- **Issuer.** Free domain-validated (DV) issuers — Let's Encrypt, ZeroSSL,
  Google Trust Services — are everywhere and legitimate on their own. But they
  are also the default for disposable and targeted infrastructure because they
  are instant, free, and anonymous. A free DV certificate minted days ago on a
  page that imitates a login, webmail, or payment portal is a meaningful signal
  when it stacks with youth or VPS hosting. Organization- or extended-validation
  certificates (DigiCert, Sectigo OV/EV naming a real company) point the other
  way — someone paid and passed identity vetting.
- **Name sprawl.** The union of `name_value` values reveals every subdomain that
  has ever had a certificate. A pile of names like `owa.`, `login-verify.`,
  `sso-`, `mail-secure-`, or brand look-alikes (`account-microsoft-…`) is
  classic phishing or intrusion staging. Legitimate businesses tend toward a
  stable, predictable set.
- **Served-vs-logged comparison.** Compare the certificate actually presented on
  the host — from Shodan's `data[].ssl.cert` (issuer, subject, `subjectAltName`,
  expiry) or, in a shell with egress, `openssl s_client -connect <host>:443
  -servername <host>`— against the CT history. Flag any mismatch: a served
  certificate whose subject doesn't match the domain, a self-signed certificate,
  a certificate issued days ago on an otherwise-established domain (possible
  compromise, hijack, or interception), or a served certificate that never
  appears in the CT logs at all. Agreement across CT and the live cert is
  reassuring; divergence is a lead.

Absence of a certificate is itself informative: a host serving an auth or
payment flow over plain HTTP, or with a mismatched cert, is not run by a careful
operator.

### 7. Check reputation

Determine whether anyone has flagged the indicator as malicious.

**VirusTotal** is the strongest single source. Its v2 endpoints take the key as a
query parameter, so they work through the WebFetch tool. The key lives in the
`VT_API_KEY` environment variable.

Query VirusTotal in two tiers, because the full reports are enormous and you
rarely need them.

**Tier 1 — the multi-engine verdict. Start here, always.**

```
https://www.virustotal.com/vtapi/v2/url/report?apikey=<VT_API_KEY>&resource=http://<target>/&scan=0
```

This returns roughly a tenth of the data of a full report and answers the
question you usually care about:

| Field | Use |
|---|---|
| `positives` / `total` | The headline score, e.g. 15/92. |
| `scan_date` | How current the verdict is. |
| `scans{}` | Per-engine results. Read the entries where `detected` is true and report **what** they called it — "phishing site" and "malware site" carry different meaning. Name two or three reputable engines rather than listing all 92. |
| `response_code` | `1` = VT has seen this URL, `0` = never scanned (not a finding either way). |

For most investigations Tier 1 plus the free sources settles the verdict. Stop
here when `positives` is 0 and provenance and services look clean, and say in
the report that you ran the URL-level check.

**Tier 2 — the full report. Only when you need it.**

```
https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=<VT_API_KEY>&ip=<ip>
https://www.virustotal.com/vtapi/v2/domain/report?apikey=<VT_API_KEY>&domain=<domain>
```

Escalate to Tier 2 when Tier 1 shows detections, when provenance looks bad (a
young domain, a recent ownership change, a privacy-proxied registrant on a
suspicious target), when the user is investigating an active incident, or when
you specifically need passive DNS or the hosted-versus-through distinction.
These responses can run tens of thousands of tokens, so read only these fields
and ignore the rest:

| Field | What it tells you |
|---|---|
| `detected_urls[]` | URLs **hosted on this target** that engines flag, each with `positives`/`total` and `scan_date`. Recent, high-`positives` entries are your headline finding. Read the paths: `/gate.php`, `/dropper.sh`, `/secure/login.php` reveal what the host serves. |
| `detected_communicating_samples[]` | Malware that talked to this address. High `positives` counts indicate command-and-control use. |
| `detected_downloaded_samples[]` | Malware served directly from the host. Stronger evidence than communicating samples. |
| `resolutions[]` | Passive DNS: hostnames that resolved here, with `last_resolved`. Many throwaway dynamic-DNS names (`*.ddnsfree.com`, `*.kozow.com`, `*.casacam.net`) suggest abuse infrastructure. |
| `as_owner`, `asn`, `country` | Corroborates your hosting data. |

Note that v2 has no `last_analysis_stats`; that field belongs to the v3 API,
which needs an `x-apikey` header the WebFetch tool cannot send. The bundled
script uses v3 and reports `malicious`/`suspicious` counts instead. Either
version answers the question — just describe what you actually measured rather
than inventing an "N/90 engines" figure the v2 response doesn't contain.

**Distinguish hosted-on from passing-through.** This matters most on shared
infrastructure such as Tor exits, VPN endpoints, CDNs, and cloud load balancers.
Malware samples that *communicate through* an address say little about its
operator, because anyone can route traffic through shared infrastructure. URLs
and downloaded samples *served from* the address are far stronger evidence,
because they mean something is listening there. Say which kind you found; the
difference frequently separates Medium from High.

**Other reputation sources:**

- **`WebSearch`** — query the raw indicator, for example `"185.220.101.1" abuse`
  or `sketchy-domain.com malware`. Surfaces AbuseIPDB scores, blocklist entries,
  sandbox reports, and vendor writeups. Use it to corroborate VirusTotal, and
  rely on it entirely when no key is set.
- **Shodan tags** — treat `malware`, `compromised`, `botnet_cc`, `honeypot`, and
  `tor` as reputation signals.

Absence of evidence is not evidence of safety. Write "no negative reputation
found" rather than "clean," and name the sources you checked.

## Keep the investigation cheap

Two sources dominate the cost of a netcheck run, and both have a small
alternative. Reaching for the expensive version by reflex can triple the cost of
an investigation that the cheap sources would have settled.

| Question | Cheap first | Expensive, on signal |
|---|---|---|
| Is it flagged? | VirusTotal `url/report` | VirusTotal `ip-address/report` or `domain/report` |
| What's exposed? | `internetdb.shodan.io` | `api.shodan.io/shodan/host` |

The order matters. Run the free sources and the Tier 1 checks first, then decide
whether anything you found justifies a full report. A nineteen-year-old domain
on a corporate registrar with transfer locks, clean InternetDB results, and
`positives: 0` does not need passive DNS pulled. A domain registered last month
behind a privacy proxy does.

When you do need a full report, two habits keep it manageable:

- **Read selectively.** Pull the handful of fields listed for that source and
  ignore the rest. Never quote PEM certificate chains, raw HTML bodies, or long
  sample hash lists into your report.
- **Isolate it if you can.** If subagents are available, have one fetch the large
  response and return only a short digest — the score, the notable URLs or
  hostnames, and the hosted-versus-through split. The bulky payload then stays
  out of the main context instead of being carried through the rest of the
  conversation. In a shell with internet, `scripts/netcheck.py` achieves the same
  thing by filtering server responses down to a compact JSON object before you
  ever see them.

Say in the report which tier you ran. "VirusTotal URL check: 0/92, full report
not pulled" is an honest and useful line — it tells the analyst exactly how deep
you looked.

## Write the summary in Google technical writing style

The summary is the part an analyst actually reads. Follow Google's technical
writing standards, because they produce prose that a reader scans quickly and
cannot misread:

- **State the conclusion first.** Open with what the indicator is and the risk
  call. Don't build to it.
- **Use active voice and present tense.** Write "Cloudflare hosts the domain,"
  not "the domain is hosted by Cloudflare."
- **Keep sentences short.** One idea per sentence. Aim under 25 words.
- **Address the reader as "you."** Write "block this at the edge," not "one
  might consider blocking."
- **Define terms and expand abbreviations on first use.** Write "AS60729
  (autonomous system, the network that announces this address range)."
- **Cut filler.** Delete "basically," "very," "it should be noted that," and
  "in order to." Replace vague words with specific ones.
- **Avoid ambiguous pronouns.** Write "this certificate," not "this."
- **Never hedge to sound safe.** If the data is thin, say which data is missing.

Hold the summary to **one paragraph of three to five sentences**. Don't write a
second paragraph — if you're reaching for one, the overflow belongs in Notes.
Be technical and concrete: name the ASN, the registrar, the ports, and the
dates. Prefer a specific fact over an adjective.

Length is a discipline, not an afterthought. An analyst triaging a queue reads
the verdict and the summary; everything else is reference. Resist the pull to
explain every observation you made. If a sentence doesn't change what the reader
does next, cut it.

**Before (verbose, passive, hedged):**
> It should be noted that this domain appears to possibly be somewhat recently
> registered, and it seems that it may be hosted on infrastructure that has been
> associated with various kinds of questionable activity in the past.

**After (Google style):**
> A privacy-protected registrant registered `login-secure-verify.com` 9 days ago
> through a bulk registrar. It resolves to 45.83.142.7 on a Dutch bulletproof
> host (AS209588) and serves a login page under a 4-day-old certificate. Block
> it at the edge.

## Output format

Produce these parts in this order. Lead with the verdict, because an analyst
reads top-down and wants the conclusion first.

```
## netcheck: <target>  —  Risk: <Low | Medium | High>

<Three to five sentences in Google technical writing style. What the indicator
is, who owns it and since when, what stands out, and why you assigned that
risk.>

### Facts
| Field | Value |
|---|---|
| Indicator | <target> (IP or domain) |
| Resolved IP | |
| Reverse DNS / hostnames | |
| Registered | <date> (<age>) |
| Last record change | <date> (<how long ago>) |
| Registrar | <name> (<reputation note>) |
| Registrant | <org, country, or "privacy-protected"> |
| Domain status | <EPP locks, e.g. clientTransferProhibited> |
| Network owner | |
| Hosting / ISP | |
| Hosting type | <established cloud/CDN, commodity VPS, bulletproof, residential> |
| Country | |
| ASN | AS#### (<name>) |
| Nameservers | |
| MX | |
| Open ports | |
| Services | |
| Known CVEs | |
| TLS cert (served) | <issuer, subject, expiry; note self-signed or mismatch> |
| Certificate history | <first-issued date from CT, notable issuers, subdomain sprawl, or "not reached"> |
| VirusTotal | <flagged URLs with positives/total and date, or malicious-engine count from v3, or "not reached"> |
| VT passive DNS | <notable hostnames that resolved here; omit if unremarkable> |
| Other reputation | <Shodan tags, blocklists, search findings> |
| Sources reached | <list; name any that failed> |

### Notes
<Up to five short bullets. Caveats, gaps, or leads worth a human's
follow-up. Omit this section if there are none.>
```

Include a row only when you have a value or a meaningful "not reached" for it.
Keep a row when its emptiness is informative, such as "Open ports: none found."
Registration rows apply to domains; for an IP, use the network allocation rows.

Keep the Notes section to five bullets at most, and put only decision-relevant
material there. Notes are for what the table can't express: a caveat that
changes how to read a fact, a gap that limits confidence, or a lead worth
chasing. They are not a place to restate the table or narrate your process. If
you find yourself writing a sixth bullet, the summary probably needs one better
sentence instead.

## Assign the risk verdict

The verdict is a judgment call, not a formula. Explain your reasoning in the
summary so a human can disagree.

**Use exactly one of `Low`, `Medium`, or `High` in the header.** Don't qualify
it, hyphenate it, or invent a compound label. Downstream readers and tooling key
off that single word, so "Low (infrastructure) / review before installing"
breaks the contract even though the underlying thought is sound.

That thought is often worth keeping, though. The verdict rates **the indicator**
— is this host or domain hostile? A clean indicator can still front a product,
vendor, or download that deserves scrutiny, and saying so is good analysis. Put
it in the summary's last sentence or the first Note, and keep the header word
clean. For example: header `Risk: Low`, then "The domain and hosting are clean;
the desktop agent it distributes is a separate privacy review."

**A clean reputation is not a Low verdict.** This is the most common way netcheck
under-calls a threat. Reputation feeds — VirusTotal, blocklists, AbuseIPDB — are
lagging indicators built from *observed* mass abuse. The infrastructure used in
targeted intrusions is designed to stay out of them. Advanced persistent threat
(APT) and nation-state operators register or repurpose a domain, point it at a
single rented server, stand up a fresh certificate, use it against a handful of
chosen targets, and retire it — often before any scanner samples it. So a
"nobody has flagged this" result is the *expected* state for the most dangerous
infrastructure, not evidence of safety. Do not let an empty reputation section
pull the verdict to Low on its own.

**Recognize targeted-intrusion tradecraft.** Weigh the shape of the
infrastructure, not just its reputation. The following pattern recurs across
APT and nation-state staging and should raise the floor to at least Medium even
with zero detections, and toward High when several stack:

- A domain or subdomain that **impersonates** a real brand, product, or service
  the target would trust — typo-squats and combo-squats like
  `microsoft-update-verify.com`, `outlook-secure-login.net`, or
  `<vendor>-sso.help`.
- **Youth that clusters** across signals: registration, first certificate, and
  first passive-DNS resolution all landing within the same recent window. Staged
  infrastructure is built all at once.
- A **minimal, purpose-built footprint** — one rented VPS, one or two open ports
  (often just 443), a single fresh DV certificate, little or no legitimate web
  content. Real businesses accrete services and history; staging servers don't.
- **Anonymity at every layer** — privacy-proxied registrant, commodity or
  crypto-friendly registrar, anonymous VPS or bulletproof hosting, free DV cert.
  Any one is normal; the full stack together is a profile.
- **Deliberate evasion** — hosting chosen to frustrate takedown or attribution
  (bulletproof providers, fast-flux passive DNS, residential-proxy fronting).

None of these requires a detection to matter. When the infrastructure fits this
profile, say so plainly in the summary and rate it on the tradecraft, not on the
empty blocklist.

**Toward High:**

- VirusTotal reports malicious detections.
- Shodan tags include `malware`, `compromised`, or `botnet_cc`.
- The domain is days or weeks old and already runs mail, authentication, or
  payment pages.
- The registrant or registrar changed recently and the change lines up with the
  activity under investigation.
- Exposed services carry known-exploited CVEs.
- Hosting sits on a bulletproof provider, or the certificate doesn't match the
  domain.
- The infrastructure fits the targeted-intrusion profile above — an
  impersonation domain on a fresh VPS with a days-old DV certificate and a
  single-purpose footprint — even with no detections. Tradecraft this clean is a
  reason to worry, not to relax.
- The served certificate is self-signed, mismatched, or absent on a page that
  handles credentials or payments.

**Toward Medium:**

- The domain is young, roughly under six months, but shows no active detections.
- The record changed recently without a clear explanation.
- The registrar has a weak abuse-handling reputation.
- The registrant is privacy-protected and other signals are ambiguous.
- Exposed services run dated software with no known exploitation.
- The host runs on a commodity VPS or anonymous datacenter range while
  presenting itself as a real service, and nothing affirmatively vouches for the
  operator.
- The certificate history is thin or recent — a first-ever certificate minted
  lately on an otherwise-older domain, or a lone fresh DV cert — without a clear
  benign explanation.
- Reputation is clean but the infrastructure is anonymous end to end (privacy
  registrant, commodity registrar, VPS, free DV cert). Clean-but-anonymous is
  Medium, not Low.
- Data is partial enough to leave real uncertainty.

**Toward Low.** Low is an affirmative judgment that the indicator looks
legitimate — reserve it for when positive evidence of a real operator is
present, not merely when nothing bad turned up. Lean Low only when *most* of
these hold and none of the Medium/High signals do:

- The domain has years of stable registration with no recent ownership change,
  corroborated by a certificate history that goes back comparably far.
- A reputable registrar sponsors it, and transfer locks are set.
- A named registrant, or an organization- or extended-validation certificate,
  matches the site's claimed operator.
- Hosting runs on established cloud or CDN infrastructure under a recognizable
  owner — not an anonymous VPS.
- No exposed-service, CVE, reputation, or targeted-tradecraft red flags appear
  in the sources you reached.

If the only thing supporting Low is the absence of detections, that is not
enough — default to Medium and name what's missing.

When data is thin, don't overclaim. "Medium — limited data" tells the analyst to
look closer, which serves them better than a confident "Low" built on two
sources. State what would change your assessment.

## Reference

Read `references/sources.md` for the full endpoint catalog, authentication
details, exact response fields, and per-source failure behavior. Consult it when
a lookup returns something unfamiliar or you need an alternate source.