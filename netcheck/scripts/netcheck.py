#!/usr/bin/env python3
"""
netcheck collector — gathers OSINT facts about an IP address or domain.

Design: this script only COLLECTS data and prints it as JSON. It does not
judge, summarize, or rate risk — that is the model's job, because judgement
benefits from context the raw data can't capture. Keeping collection
deterministic here means every investigation starts from the same reliable
base and the model spends its effort on analysis, not on plumbing.

Sources, and why each is here:
  - dig            DNS records + reverse DNS (the ground truth of what resolves)
  - RDAP (HTTP)    registration / ownership (modern replacement for whois;
                   works without the whois binary, which is often absent)
  - ip-api.com     geolocation + ASN + hosting org (free, no key)
  - VirusTotal     reputation / detections     (needs VT_API_KEY)
  - Shodan         open ports, banners, vulns  (needs SHODAN_API_KEY)
  - openssl        TLS certificate on :443     (issuer, validity, SANs)

Every source degrades gracefully: a failure is recorded under that source's
"error" key and collection continues, so one dead API never sinks the report.

Usage:  python3 netcheck.py <ip-or-domain>
Env:    VT_API_KEY, SHODAN_API_KEY  (optional; sources skip cleanly if unset)
"""
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.error

TIMEOUT = 12


def classify(target):
    """Return 'ipv4', 'ipv6', or 'domain'. Trust the parser over regexes."""
    try:
        ip = ipaddress.ip_address(target)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        return "domain"


def http_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def doh(name, rtype):
    """DNS over HTTPS via Google. Works anywhere HTTPS egress exists, even
    where UDP/53 is firewalled (common in sandboxes)."""
    try:
        d = http_json(f"https://dns.google/resolve?name={name}&type={rtype}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    ans = d.get("Answer", [])
    return [a["data"].rstrip(".") for a in ans if "data" in a]


def dig(name, rtype):
    """Prefer the dig binary (fast, when UDP/53 is open); fall back to DoH."""
    try:
        out = subprocess.run(
            ["dig", "+short", name, rtype],
            capture_output=True, text=True, timeout=TIMEOUT,
        ).stdout.strip()
        lines = [ln for ln in out.splitlines() if ln]
        # dig prints diagnostic ";; ..." lines to stdout on network failure.
        if lines and not any(ln.startswith(";") for ln in lines):
            return lines
    except Exception:  # noqa: BLE001
        pass
    return doh(name, rtype)


def collect_dns(target, kind):
    dns = {}
    if kind == "domain":
        for rt in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            dns[rt] = dig(target, rt)
    else:  # reverse DNS for an IP
        try:
            dns["PTR"] = socket.gethostbyaddr(target)[0]
        except Exception as e:  # noqa: BLE001
            dns["PTR"] = {"error": str(e)}
    return dns


def resolve_ip(target, kind):
    """Best-effort single IP for a target so IP-only sources work on domains."""
    if kind != "domain":
        return target
    a = dig(target, "A")
    if isinstance(a, list) and a:
        return a[0]
    try:
        return socket.gethostbyname(target)
    except Exception:  # noqa: BLE001
        pass
    d = doh(target, "A")
    return d[0] if isinstance(d, list) and d else None


def collect_rdap(target, kind):
    kindpath = "ip" if kind in ("ipv4", "ipv6") else "domain"
    try:
        data = http_json(f"https://rdap.org/{kindpath}/{target}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    out = {}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    out["registration"] = events.get("registration")
    out["expiration"] = events.get("expiration")
    out["last_changed"] = events.get("last changed")
    # Registrant / owning org
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [None, []])[1]
        name = next((f[3] for f in vcard if f[0] == "fn"), None)
        if "registrar" in roles and name:
            out["registrar"] = name
        if ("registrant" in roles or "administrative" in roles) and name:
            out.setdefault("registrant", name)
    out["name"] = data.get("name") or data.get("ldhName")
    out["handle"] = data.get("handle")
    if kind != "domain":
        out["network_name"] = data.get("name")
        out["cidr"] = ", ".join(
            f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
            for c in data.get("cidr0_cidrs", [])
        ) or None
    out["status"] = data.get("status")
    return {k: v for k, v in out.items() if v}


def collect_whois(target, kind):
    """Ownership provenance for domains: age, last change, registrar, locks.

    This is the highest-signal block in the report. Age and recency-of-change
    separate established businesses from disposable attack domains better than
    any single technical indicator, so the ages are precomputed here to keep the
    analysis honest rather than eyeballed from raw timestamps.
    """
    if kind != "domain":
        return {"skipped": "whois provenance applies to domains; see rdap for IPs"}
    try:
        raw = urllib.request.urlopen(
            urllib.request.Request(f"https://api.whois.vu/?q={target}"), timeout=TIMEOUT
        ).read().decode("utf-8", "replace")
        d = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    now = dt.datetime.now(dt.timezone.utc)

    def when(ts):
        if not isinstance(ts, (int, float)):
            return None, None
        t = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
        return t.strftime("%Y-%m-%d"), (now - t).days

    created, age_days = when(d.get("created"))
    updated, changed_days = when(d.get("updated"))
    expires, _ = when(d.get("expires"))

    out = {
        "available": d.get("available"),
        "registrar": d.get("registrar"),
        "created": created,
        "age_days": age_days,
        "updated": updated,
        "days_since_change": changed_days,
        "expires": expires,
        "statuses": d.get("statuses"),
    }
    # Pull registrant identity out of the raw WHOIS text.
    txt = d.get("whois") or ""
    for field, key in [("Registrant Organization", "registrant_org"),
                       ("Registrant Country", "registrant_country"),
                       ("Registrar Abuse Contact Email", "registrar_abuse_contact")]:
        m = re.search(rf"{field}:\s*(.+)", txt)
        if m:
            out[key] = m.group(1).strip()

    # Flags the analyst should not have to compute by hand.
    flags = []
    if age_days is not None and age_days < 30:
        flags.append(f"domain is only {age_days} days old")
    elif age_days is not None and age_days < 180:
        flags.append(f"domain is young ({age_days} days)")
    if changed_days is not None and changed_days < 90:
        flags.append(f"record changed {changed_days} days ago")
    if not any("TransferProhibited" in s for s in (d.get("statuses") or [])):
        flags.append("no transfer lock set")
    out["provenance_flags"] = flags or ["no provenance red flags"]
    return {k: v for k, v in out.items() if v is not None}


def collect_ip_allocation(ip):
    """Network allocation provenance — the IP-side equivalent of WHOIS age.

    RIPEstat mirrors every regional registry, so this works for addresses
    anywhere. `created` and `last-modified` on the allocation carry the same
    weight as a domain's registration and change dates.
    """
    if not ip:
        return {"error": "no resolvable IP"}
    try:
        d = http_json(f"https://stat.ripe.net/data/whois/data.json?resource={ip}")
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    recs = d.get("data", {}).get("records", [])
    flat = {}
    for group in recs:
        for item in group:
            k, v = item.get("key"), item.get("value")
            if not k:
                continue
            if k == "mnt-by":
                flat.setdefault("maintainers", []).append(v)
            else:
                flat.setdefault(k, v)

    now = dt.datetime.now(dt.timezone.utc)

    def age(val):
        try:
            t = dt.datetime.strptime(val, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
            return (now - t).days
        except Exception:  # noqa: BLE001
            return None

    origin = None
    for group in d.get("data", {}).get("irr_records", []):
        for item in group:
            if item.get("key") == "origin":
                origin = f"AS{item.get('value')}"
                break
        if origin:
            break

    out = {
        "inetnum": flat.get("inetnum"),
        "netname": flat.get("netname"),
        "org": flat.get("org"),
        "country": flat.get("country"),
        "status": flat.get("status"),
        "maintainers": flat.get("maintainers"),
        "allocated": flat.get("created"),
        "allocation_age_days": age(flat.get("created", "")),
        "last_modified": flat.get("last-modified"),
        "days_since_change": age(flat.get("last-modified", "")),
        "announcing_asn": origin,
    }
    return {k: v for k, v in out.items() if v is not None}


def collect_geo_asn(ip):
    if not ip:
        return {"error": "no resolvable IP"}
    # ipwho.is is free, no key, and reachable from most sandboxes.
    try:
        d = http_json(f"https://ipwho.is/{ip}")
        if d.get("success"):
            conn = d.get("connection", {})
            return {
                "ip": ip,
                "country": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "isp": conn.get("isp"),
                "org": conn.get("org"),
                "asn": f"AS{conn.get('asn')}" if conn.get("asn") else None,
                "asn_domain": conn.get("domain"),
            }
    except Exception:  # noqa: BLE001
        pass
    # Fallback: ip-api.com (no key).
    try:
        d = http_json(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,regionName,city,isp,org,as,asname,hosting"
        )
        if d.get("status") == "success":
            return {
                "ip": ip, "country": d.get("country"), "region": d.get("regionName"),
                "city": d.get("city"), "isp": d.get("isp"), "org": d.get("org"),
                "asn": d.get("as"), "asn_name": d.get("asname"), "hosting": d.get("hosting"),
            }
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    return {"error": "geo/ASN lookup failed"}


def collect_vt_url_score(target):
    """Tier 1 VirusTotal: the multi-engine score for the target's root URL.

    This is deliberately the first VT call. It costs a fraction of a full
    report and answers the question that usually decides the verdict, so an
    investigation that comes back clean never has to pay for the big payload.
    """
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"skipped": "VT_API_KEY not set"}
    try:
        d = http_json(
            "https://www.virustotal.com/vtapi/v2/url/report"
            f"?apikey={key}&resource=http://{target}/&scan=0"
        )
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    if d.get("response_code") != 1:
        return {"note": "URL not present in VirusTotal dataset"}
    flagged = {
        eng: r.get("result")
        for eng, r in (d.get("scans") or {}).items()
        if r.get("detected")
    }
    return {
        "positives": d.get("positives"),
        "total": d.get("total"),
        "scan_date": d.get("scan_date"),
        "flagged_by": flagged,
    }


def collect_virustotal(target, kind):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"skipped": "VT_API_KEY not set"}
    path = "ip_addresses" if kind in ("ipv4", "ipv6") else "domains"
    try:
        d = http_json(
            f"https://www.virustotal.com/api/v3/{path}/{target}",
            headers={"x-apikey": key},
        )
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    attr = d.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "reputation": attr.get("reputation"),
        "categories": attr.get("categories"),
        "tags": attr.get("tags"),
    }


def collect_internetdb(ip):
    """Shodan's free, no-key InternetDB: ports, CVEs, tags. A useful floor
    when no SHODAN_API_KEY is available."""
    if not ip:
        return {"error": "no resolvable IP"}
    try:
        d = http_json(f"https://internetdb.shodan.io/{ip}")
        return {"ports": d.get("ports"), "vulns": d.get("vulns"),
                "tags": d.get("tags"), "hostnames": d.get("hostnames"),
                "cpes": d.get("cpes")}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"note": "no InternetDB data for this host"}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def collect_shodan(ip):
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return {"skipped": "SHODAN_API_KEY not set; see internetdb section"}
    if not ip:
        return {"error": "no resolvable IP"}
    try:
        d = http_json(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"note": "no Shodan data for this host"}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    return {
        "ports": d.get("ports"),
        "hostnames": d.get("hostnames"),
        "tags": d.get("tags"),
        "vulns": d.get("vulns"),
        "os": d.get("os"),
        "last_update": d.get("last_update"),
        "services": sorted({
            f"{s.get('port')}/{s.get('_shodan', {}).get('module', '?')}"
            for s in d.get("data", [])
        }),
    }


def collect_tls(target, kind):
    """Fetch the leaf cert on :443. Works for domains and IPs with a cert."""
    host = target
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if kind == "domain" else None) as ss:
                cert = ss.getpeercert()
        if not cert:  # verify_mode NONE can yield empty; fall back to openssl
            return _tls_openssl(host)
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        return {
            "subject_cn": subj.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": sans[:25],
        }
    except Exception as e:  # noqa: BLE001
        return _tls_openssl(host, err=str(e))


def _tls_openssl(host, err=None):
    try:
        p = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:443",
             "-servername", host, "-brief"],
            input="", capture_output=True, text=True, timeout=TIMEOUT,
        )
        txt = p.stderr + p.stdout
        m = re.search(r"subject=(.+)", txt)
        i = re.search(r"issuer=(.+)", txt)
        if m or i:
            return {"subject": m.group(1).strip() if m else None,
                    "issuer": i.group(1).strip() if i else None}
    except Exception:  # noqa: BLE001
        pass
    return {"error": err or "no TLS on :443"}


def _summarize_ct(rows, source, name_key, issuer_key):
    """Fold a CT issuance list into the provenance signals that matter:
    first-issuance date, issuer mix, and subdomain sprawl."""
    names, issuers, earliest, latest = set(), {}, None, None
    for r in rows:
        raw = r.get(name_key)
        parts = raw if isinstance(raw, list) else (raw or "").splitlines()
        for n in parts:
            n = str(n).strip().lower()
            if n:
                names.add(n)
        iss = r.get(issuer_key)
        if isinstance(iss, dict):  # certspotter: issuer is an object
            iss = iss.get("name")
        iss = iss or "unknown"
        issuers[iss] = issuers.get(iss, 0) + 1
        nb = r.get("not_before")
        if nb:
            earliest = nb if earliest is None or nb < earliest else earliest
            latest = nb if latest is None or nb > latest else latest
    top_issuers = sorted(issuers.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return {
        "source": source,
        "certs_logged": len(rows),
        "first_issued": earliest,
        "most_recent_issued": latest,
        "issuers": [f"{name} ({count})" for name, count in top_issuers],
        "distinct_names": len(names),
        "name_sample": sorted(names)[:30],
    }


def collect_ct(target, kind):
    """Certificate Transparency history, with a fallback cascade.

    crt.sh is the primary source but frequently returns empty under load, so on
    an empty/failed result we fall through to SSLMate's Cert Spotter. Both
    summarize the issuance timeline and subdomain sprawl rather than dumping
    every logged cert. When neither answers, the caller still has the served
    certificate from collect_tls().
    """
    if kind != "domain":
        return {"skipped": "certificate history applies to domains"}

    # 1. crt.sh
    try:
        rows = http_json(f"https://crt.sh/?q={target}&output=json")
        if isinstance(rows, list) and rows:
            return _summarize_ct(rows, "crt.sh", "name_value", "issuer_name")
        crt_note = "crt.sh returned empty"
    except Exception as e:  # noqa: BLE001
        crt_note = f"crt.sh error: {e}"

    # 2. Cert Spotter (alternate CT source)
    try:
        headers = {}
        key = os.environ.get("CERTSPOTTER_API_KEY") or os.environ.get("SSLMATE_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        url = ("https://api.certspotter.com/v1/issuances?domain=" + target +
               "&include_subdomains=true&expand=dns_names&expand=issuer"
               "&expand=not_before&expand=not_after")
        rows = http_json(url, headers=headers or None)
        if isinstance(rows, list) and rows:
            return _summarize_ct(rows, "certspotter", "dns_names", "issuer")
        cs_note = "certspotter returned empty"
    except Exception as e:  # noqa: BLE001
        cs_note = f"certspotter error: {e}"

    return {"note": f"no CT history reached ({crt_note}; {cs_note}) — "
                    "rely on the served certificate in 'tls'"}


def main():
    if len(sys.argv) != 2:
        print("usage: netcheck.py <ip-or-domain>", file=sys.stderr)
        sys.exit(2)
    target = sys.argv[1].strip().lower()
    # Tolerate a pasted URL — reduce to its host.
    target = re.sub(r"^\w+://", "", target).split("/")[0].split(":")[0]
    kind = classify(target)
    ip = resolve_ip(target, kind)

    report = {
        "target": target,
        "type": kind,
        "resolved_ip": ip,
        "whois": collect_whois(target, kind),
        "ip_allocation": collect_ip_allocation(ip),
        "dns": collect_dns(target, kind),
        "rdap": collect_rdap(target, kind),
        "geo_asn": collect_geo_asn(ip),
        "vt_url_score": collect_vt_url_score(target),
        "virustotal": collect_virustotal(target, kind),
        "shodan": collect_shodan(ip),
        "internetdb": collect_internetdb(ip),
        "tls": collect_tls(target, kind),
        "cert_transparency": collect_ct(target, kind),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
