# netcheck source catalog

Every source netcheck can use, how to reach it, what to read from the response,
and how it fails. Sources are grouped by the question they answer. Each one is
independent — use what's reachable, note what isn't.

Two access methods are referenced throughout:
- **WebFetch tool** — `mcp__workspace__web_fetch` / `WebFetch`. The reliable
  path in Cowork/sandboxes. Can only do GET with URL-embedded params (no custom
  headers).
- **Script/shell** — `scripts/netcheck.py` or direct `curl`, only where the
  shell has outbound internet. Can send headers, so it's the only way to use
  VirusTotal.

---

## DNS — where does it point, who mails/serves it

### Google DNS-over-HTTPS  (no key, WebFetch-friendly)
```
https://dns.google/resolve?name=<name>&type=<A|AAAA|MX|NS|TXT|SOA|PTR|CNAME>
```
Read: `Answer[].data`. `Status: 0` means success; `Status: 3` is NXDOMAIN
(the name doesn't exist — itself a finding). Works where UDP/53 is firewalled.

### Cloudflare DoH  (fallback, no key)
```
https://cloudflare-dns.com/dns-query?name=<name>&type=<type>
```
Requires header `accept: application/dns-json` — so shell/curl only, not the
WebFetch tool. Use only if Google DoH is down.

### `dig`  (shell with UDP/53 open)
`dig +short <name> <type>`. Fastest when it works. In sandboxes it usually
prints `;; ... network unreachable` — that's the cue to switch to DoH.

---

## Registration / ownership provenance

This group answers the highest-value questions in netcheck: how old is this
domain, has its ownership changed recently, and who sponsors it.

### whois.vu  (no key, WebFetch-friendly — PRIMARY for domains)
```
https://api.whois.vu/?q=<domain>
```
Returns JSON as `text/plain`, so the WebFetch tool renders it correctly (unlike
RDAP). Fields:

| Field | Use |
|---|---|
| `created` | Unix timestamp of registration. Convert, then compute age. Under 30 days is a strong suspicion signal. |
| `updated` | Unix timestamp of last record change. **The change-detection signal.** Recent changes on an old domain suggest transfer, resale, or hijack. |
| `expires` | Unix timestamp of expiry. Far-future expiry implies long-term investment. |
| `registrar` | Sponsoring registrar. Judge its abuse-handling reputation. |
| `statuses` | EPP status codes. `clientTransferProhibited`, `clientUpdateProhibited`, and `clientDeleteProhibited` show deliberate anti-hijack locks. |
| `whois` | Raw WHOIS text. Parse `Registrant Organization`, `Registrant Country`, and `Registrar Abuse Contact` from it. |
| `available` | `"yes"` means the domain is unregistered — a finding in itself. |

Convert timestamps with `date -d @<ts>` or Python
`datetime.utcfromtimestamp(ts)`. Rate-limited on the free tier; if it returns an
error or a quota message, fall back to WebSearch.

### RIPEstat  (no key, WebFetch-friendly — PRIMARY for IP allocation)
```
https://stat.ripe.net/data/whois/data.json?resource=<ip>
```
Returns `application/json` and covers **all** regional registries (RIPE, ARIN,
APNIC, LACNIC, AFRINIC), so it works regardless of where the address lives.

`data.records[]` is a list of key/value pair lists. Useful keys:

| Key | Use |
|---|---|
| `inetnum` | The assigned range, e.g. `185.220.101.0/27`. Narrower is more specific than the /8 delegation. |
| `netname` | Short name of the assignment, e.g. `ARTIKEL10`. |
| `org` | Organization handle. |
| `country` | Assigned country. |
| `status` | e.g. `ASSIGNED PA`. |
| `mnt-by` | Maintainer objects. Often names the real operator, e.g. `ZWIEBELFREUNDE` for Tor infrastructure. |
| `created` | **Allocation age.** Apply the same reasoning as a domain's `created`. |
| `last-modified` | **Allocation change signal.** Recent re-assignment deserves the same suspicion as a recent registrar change. |

`data.irr_records[]` carries the routing view: `route` and `origin` (the
announcing AS number).

### ARIN WHOIS text  (no key, WebFetch-friendly — North America only)
```
https://whois.arin.net/rest/ip/<ip>.txt
```
Returns `text/plain`, which renders correctly through the WebFetch tool (unlike
RDAP). Read `NetRange`, `CIDR`, `NetName`, `NetType`, `Organization`,
`RegDate`, and `Updated`.

Two traps:
- **Outside the ARIN region it returns a delegation stub**, not the real owner.
  `NetType: Allocated to RIPE NCC` with `NetName: RIPE-185` means "ask RIPE" —
  use RIPEstat instead. Reporting "RIPE NCC" as the owner is wrong.
- **`RegDate` reflects the registry record, not first control** of the block. A
  recent `RegDate` on long-established infrastructure is a record refresh, not a
  new allocation. Don't read it as a youth signal without corroboration.

### WebSearch  (registration fallback)
Query `<domain> whois registrar creation date` or search a WHOIS lookup site.
This reliably recovers registrar, creation date, and registrant organization
when the API is rate-limited. Attribute the source in the report.

### RDAP via rdap.org  (no key, often undecodable via WebFetch)
```
https://rdap.org/domain/<domain>
https://rdap.org/ip/<ip>
```
rdap.org redirects to the authoritative registry. Read:
- `events[]` → `eventAction: "registration" | "expiration" | "last changed"`
  with `eventDate`.
- `entities[]` → the one whose `roles` includes `registrar` or `registrant`;
  the display name is under `vcardArray[1]` in the `fn` entry.
- IPs: `name`, `handle`, `cidr0_cidrs[]`, `status[]`.

Known issue: RDAP responds with `Content-Type: application/rdap+json`, which the
WebFetch tool commonly renders as `[binary data]`, and `rdap.org` may return an
empty body in sandboxes. **For domains, prefer whois.vu above.** RDAP remains
useful for IP allocations via the bundled script (which decodes it fine), or the
regional server directly, e.g. `https://rdap.arin.net/registry/ip/<ip>`. If it
fails, record "registration: not reached" and continue.

---

## Geolocation, hosting, ASN

### ipwho.is  (no key, WebFetch-friendly — primary)
```
https://ipwho.is/<ip>
```
Read: `country`, `region`, `city`, `connection.isp`, `connection.org`,
`connection.asn`, `connection.domain`. `success: false` means it couldn't
resolve — fall back to ip-api.

### ip-api.com  (no key, fallback)
```
http://ip-api.com/json/<ip>?fields=status,message,country,regionName,city,isp,org,as,asname,hosting
```
Read: `country`, `city`, `isp`, `org`, `as`, `asname`, `hosting` (bool — true
often means datacenter/VPN). Free tier is HTTP-only and rate-limited (~45/min);
may be blocked on some fetch allowlists.

**Classify the hosting into a tier, because it is a provenance signal.**
Established cloud/CDN (AWS, GCP, Azure, Cloudflare, Fastly, Akamai) is neutral.
Commodity VPS and low-cost hosting — a rented virtual server with little identity
checking — deserves elevated suspicion, because it is the default staging ground
for both commodity crews and targeted intruders; a VPS fronting something that
claims to be a real company or portal is a mismatch worth flagging. Bulletproof,
residential-proxy, and Tor-associated networks are the highest concern. When
`hosting` is true and no recognizable brand owns the range, treat it as anonymous
datacenter infrastructure and weight toward Medium. `WebSearch` the ASN or `org`
name for its abuse reputation when unfamiliar.

---

## Exposed services, ports, CVEs, TLS

### Shodan InternetDB  (no key, WebFetch-friendly — always try)
```
https://internetdb.shodan.io/<ip>
```
Read: `ports[]`, `vulns[]` (CVE IDs — populated means known-vulnerable),
`tags[]`, `hostnames[]`, `cpes[]`. 404 = Shodan has never seen the host (note
it; not itself alarming). This is the dependable floor for exposed-service data.

### Shodan host API  (needs SHODAN_API_KEY, WebFetch-friendly — key is a query param)
```
https://api.shodan.io/shodan/host/<ip>?key=<SHODAN_API_KEY>
```
Richer than InternetDB. Read: `ports[]`, `vulns[]`, `tags[]`, `os`,
`hostnames[]`, and per-service `data[]` entries (`port`, `product`, `version`,
`_shodan.module`). TLS lives in `data[].ssl.cert` → `issuer`, `subject`,
`expires`, `subjectAltName`. 404 = host not in Shodan. 401 = bad/expired key.

### openssl  (shell, direct TLS grab)
`openssl s_client -connect <host>:443 -servername <host> -brief` for issuer and
subject when you want the live cert rather than Shodan's cached one. Shell with
egress only.

### crt.sh Certificate Transparency  (no key, WebFetch-friendly — cert history)
```
https://crt.sh/?q=<domain>&output=json
```
Returns a JSON array, one object per publicly-logged certificate. Fields:

| Field | Use |
|---|---|
| `not_before` | When the cert became valid. The **earliest** across all entries approximates when the domain first served HTTPS — a first-issuance age to compare against WHOIS `created`. |
| `not_after` | Expiry. |
| `issuer_name` | Certificate authority. Free DV issuers (Let's Encrypt, ZeroSSL, Google Trust Services) are ubiquitous but favored by disposable/targeted infra; OV/EV issuers naming a company signal identity vetting. |
| `common_name` | Primary name on the cert. |
| `name_value` | All covered names, newline-separated. The union across entries **enumerates subdomains** — watch for phishing/staging patterns (`login-verify.`, `owa.`, brand look-alikes). |
| `entry_timestamp` | When the log recorded it. |

A years-old registration whose *first ever* certificate appeared recently is a
staging/repurposing signal. crt.sh is unreliable — it frequently returns an empty
body under load, and on a restricted fetch allowlist the host may be unreachable
entirely. When it comes back empty, don't retry it; fall through the cascade
below.

### Cert Spotter  (no key for the free tier, WebFetch-friendly — alternate CT)
```
https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names&expand=issuer&expand=not_before&expand=not_after
```
SSLMate's Cert Spotter covers the same CT logs and is often up when crt.sh is
down. Returns a JSON array of issuance objects. Read `dns_names` (subdomain
enumeration), `issuer.name` (CA), and `not_before` / `not_after` (ISO dates, no
conversion needed). The keyless tier is rate-limited and unauthenticated results
can be partial; the bundled script adds an `Authorization: Bearer
<CERTSPOTTER_API_KEY>` header when that variable is set. A `429` or empty body
means fall through to the served certificate.

### Served-certificate fallback  (when no CT source answers)
If both crt.sh and Cert Spotter are unreachable — the usual case on a locked-down
WebFetch allowlist — assess the certificate the host actually presents instead of
leaving the section blank. Pull it from Shodan `data[].ssl.cert` (issuer,
subject, `subjectAltName`, expiry) via the host API, or `openssl s_client
-connect <host>:443 -servername <host>` in a shell with egress. This gives
issuer, subject, SANs, and self-signed/mismatch status, but **not** the issuance
timeline — so first-issuance age can't be established this way. Report that CT
history was unavailable and which fallback you used.

**Comparing served vs logged.** Pull the live cert from Shodan `data[].ssl.cert`
or openssl and check it against the CT timeline. Flag a served cert that is
self-signed, whose subject doesn't match the domain, that was issued days ago on
an otherwise-established domain, or that never appears in the CT logs.

---

## Reputation / threat intelligence

### VirusTotal v2 url/report  (TIER 1 — small, start here)
```
https://www.virustotal.com/vtapi/v2/url/report?apikey=<VT_API_KEY>&resource=http://<target>/&scan=0
```
Roughly a tenth the size of a full report and usually sufficient. Read:

| Field | Use |
|---|---|
| `positives` / `total` | Headline multi-engine score, e.g. 15/92. |
| `scan_date` | Currency of the verdict. |
| `scans{}` | Per-engine detail. Report only entries with `detected: true`, and quote the verdict text — "phishing site" vs "malware site" vs "malicious site" are different claims. Name two or three reputable engines; don't list all 92. |
| `response_code` | `1` = seen by VT, `0` = never scanned. |

`scan=0` returns the cached verdict without queuing a new scan, which keeps this
passive and fast.

Caveat: this reflects that one URL, not the whole host. A domain can score 0/92
on its root URL while `domain/report` shows other flagged paths. That's an
acceptable trade for triage — escalate when anything looks off.

### VirusTotal v2 full reports  (TIER 2 — very large, on signal only)
```
https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=<VT_API_KEY>&ip=<ip>
https://www.virustotal.com/vtapi/v2/domain/report?apikey=<VT_API_KEY>&domain=<domain>
```
The key rides in the URL, so this **works through the WebFetch tool**. Verified
working. An empty response body means VT rejected the key — check the key before
concluding the host is blocked.

These can run tens of thousands of tokens on a busy indicator, because they
inline every detected URL, sample, and passive-DNS record. Pull one only when
Tier 1 shows detections, provenance looks bad, or you specifically need passive
DNS or the hosted-versus-through split. Read only:

| Field | Use |
|---|---|
| `detected_urls[]` | URLs hosted on the target that engines flag: `url`, `positives`, `total`, `scan_date`. Recent + high positives = headline finding. Read the paths for intent (`/gate.php`, `/dropper.sh`, `/secure/login.php`). |
| `detected_communicating_samples[]` | Malware that contacted the address (traffic *through*). |
| `detected_downloaded_samples[]` | Malware served *from* the address. Much stronger evidence. |
| `detected_referrer_samples[]` | Samples referencing the address. |
| `resolutions[]` | Passive DNS: `hostname` + `last_resolved`. Piles of throwaway dynamic-DNS names indicate abuse infrastructure. |
| `as_owner`, `asn`, `country` | Corroborates hosting data. |
| `response_code` | `1` = found, `0` = not in dataset. |

For domains you also get `categories`, `subdomains`, and `Webutation domain info`.

v2 has **no** `last_analysis_stats` — don't report an "N/90 engines" score from
a v2 response. Describe the detected URLs and samples you actually saw.

### VirusTotal v3  (needs VT_API_KEY header — script/shell only)
```
GET https://www.virustotal.com/api/v3/domains/<domain>
GET https://www.virustotal.com/api/v3/ip_addresses/<ip>
Header: x-apikey: <VT_API_KEY>
```
Richer and better structured. Read `data.attributes.last_analysis_stats`
(`malicious`, `suspicious`, `harmless`, `undetected`),
`data.attributes.reputation`, `.categories`, `.tags`. A nonzero `malicious` is a
headline finding. The WebFetch tool cannot send headers, so use this only via
`scripts/netcheck.py` or curl where the shell has egress.

Free keys are rate-limited to roughly 4 requests per minute on both versions.

### Reading VirusTotal on shared infrastructure
On Tor exits, VPN endpoints, CDNs, and cloud load balancers, VirusTotal will
almost always look alarming, because anyone can push traffic through shared
infrastructure. Weigh the evidence types differently:

- `detected_communicating_samples` — weak attribution. Traffic *through* the
  host. Expected on any Tor exit.
- `detected_urls` and `detected_downloaded_samples` — strong attribution.
  Something is *listening and serving* on that address.

Report which kind you found. This distinction often decides Medium versus High.

### WebSearch  (reputation fallback everywhere)
When VT is out of reach, search the raw indicator: `"<indicator>" abuse`,
`<indicator> malware`, `<indicator> blocklist`. Look for AbuseIPDB confidence
scores, Spamhaus/blocklist listings, urlscan.io or sandbox reports, and vendor
threat writeups. Attribute what you find and don't overweight a single
low-quality hit.

### Signals already in hand
Shodan/InternetDB `tags` carry reputation too: `malware`, `compromised`,
`honeypot`, `tor`, `botnet_cc`, `self-signed`. Factor them into the verdict.

---

## Putting it together

A complete run typically touches: DoH (DNS) → RDAP (ownership) → ipwho.is
(hosting) → InternetDB and/or Shodan (services + CVEs) → crt.sh (certificate
history) → VirusTotal or WebSearch (reputation). You rarely get all of them;
three or four solid sources are enough for a defensible verdict as long as you're
honest in the report about which ones answered and which didn't. Remember that a
clean reputation is the *expected* state for targeted-intrusion infrastructure —
weigh provenance, hosting tier, and certificate history, not just blocklists.