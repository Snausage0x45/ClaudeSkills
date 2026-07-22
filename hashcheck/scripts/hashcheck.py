"""
hashcheck collector — gathers OSINT facts about a file hash for malware triage.
 
Design: this script only COLLECTS data and prints it as JSON. It does not judge,
summarize, or rate risk — that is the model's job, because judgement benefits
from context the raw data can't capture. Keeping collection deterministic here
means every investigation starts from the same reliable base and the model
spends its effort on analysis, not on plumbing.
 
Input may be a hash (MD5/SHA-1/SHA-256) or a path to a local file. When given a
file, the script computes all three digests and looks the file up by SHA-256; it
never executes the file.
 
Sources, and why each is here:
  - VirusTotal v3   detections + pe_info (sections/entropy) + signature_info +
                    sandbox verdicts + YARA/Sigma   (needs VT_API_KEY)
  - MalwareBazaar   family, code-signing certs, imphash, tags, vendor intel
                    (needs a free abuse.ch Auth-Key)
  - Hybrid Analysis dynamic verdict, threat score, MITRE ATT&CK  (needs a key)
  - Joe Sandbox     maliciousness score from cloud analyses      (needs a key)
 
Every source degrades gracefully: a missing key or a failed request is recorded
under that source's "error"/"skipped" key and collection continues, so one dead
API never sinks the report. The model reads what came back and reports the gaps.
 
Usage:  python3 hashcheck.py <hash-or-file>
Env (all optional; sources that lack a key are skipped, not fatal):
  VT_API_KEY                              VirusTotal
  MB_API_KEY | ABUSE_CH_API_KEY           MalwareBazaar / abuse.ch
  HYBRID_ANALYSIS_KEY | HA_API_KEY        Hybrid Analysis
  JOE_SANDBOX_KEY | JBX_API_KEY           Joe Sandbox
  JOE_SANDBOX_URL                         Joe Sandbox base (default cloud)
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
 
TIMEOUT = 20
 
HEX_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
 
 
def env(*names):
    """Return the first non-empty environment variable among names."""
    for n in names:
        v = os.environ.get(n)
        if v:
            return v.strip()
    return None
 
 
def classify_input(arg):
    """Decide whether arg is a file path or a hash string.
 
    A real, readable file wins even if its name looks hash-ish. Otherwise treat
    a clean hex string of a known length as a hash.
    """
    if os.path.isfile(arg):
        return "file", arg
    s = arg.strip().lower()
    s = re.sub(r"^(sha256:|sha1:|md5:|0x)", "", s)
    if len(s) in HEX_LENGTHS and re.fullmatch(r"[0-9a-f]+", s):
        return "hash", s
    return "invalid", arg
 
 
def hash_file(path):
    """Compute md5/sha1/sha256 in one streaming pass. Never runs the file."""
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            size += len(chunk)
            for algo in h.values():
                algo.update(chunk)
    return {
        "md5": h["md5"].hexdigest(),
        "sha1": h["sha1"].hexdigest(),
        "sha256": h["sha256"].hexdigest(),
        "size_bytes": size,
        "local_name": os.path.basename(path),
    }
 
 
def http(url, data=None, headers=None, method=None):
    """Minimal HTTP helper. data as dict -> urlencoded body (POST)."""
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        raw = r.read().decode("utf-8", "replace")
    return raw
 
 
def http_json(url, data=None, headers=None, method=None):
    return json.loads(http(url, data=data, headers=headers, method=method))
 
 
def err(e):
    """Normalize an exception into a short, greppable string."""
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}"
    return str(e)
 
 
# ---------------------------------------------------------------- VirusTotal v3
def vt_v3(h):
    key = env("VT_API_KEY")
    if not key:
        return {"skipped": "no VT_API_KEY set"}
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    try:
        d = http_json(url, headers={"x-apikey": key})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "note": "hash unknown to VirusTotal"}
        return {"error": err(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": err(e)}
 
    a = d.get("data", {}).get("attributes", {})
    out = {"found": True}
    out["last_analysis_stats"] = a.get("last_analysis_stats")
    out["type_description"] = a.get("type_description")
    out["type_tag"] = a.get("type_tag")
    out["size"] = a.get("size")
    out["meaningful_name"] = a.get("meaningful_name")
    out["names"] = (a.get("names") or [])[:8]
    out["first_submission_date"] = a.get("first_submission_date")
    out["last_analysis_date"] = a.get("last_analysis_date")
    out["reputation"] = a.get("reputation")
    out["total_votes"] = a.get("total_votes")
    out["tags"] = a.get("tags")
 
    ptc = a.get("popular_threat_classification") or {}
    out["suggested_threat_label"] = ptc.get("suggested_threat_label")
 
    # Keep only the engines that flagged it, and only the fields we use.
    results = a.get("last_analysis_results") or {}
    flags = {}
    for eng, r in results.items():
        if r.get("category") in ("malicious", "suspicious"):
            flags[eng] = {"category": r.get("category"), "result": r.get("result")}
    out["detections"] = flags
 
    sig = a.get("signature_info")
    if sig:
        out["signature_info"] = {
            k: sig.get(k)
            for k in (
                "verified", "subject", "signers", "product", "description",
                "signing date", "counter signers", "x509", "original name",
            )
            if sig.get(k) is not None
        }
 
    pe = a.get("pe_info")
    if pe:
        sections = []
        for s in (pe.get("sections") or []):
            sections.append({
                "name": s.get("name"),
                "entropy": s.get("entropy"),
                "raw_size": s.get("raw_size"),
                "virtual_size": s.get("virtual_size"),
            })
        out["pe_info"] = {
            "imphash": pe.get("imphash"),
            "entry_point": pe.get("entry_point"),
            "sections": sections,
            "import_dlls": [i.get("library_name") for i in (pe.get("import_list") or [])][:15],
        }
 
    sv = a.get("sandbox_verdicts")
    if sv:
        out["sandbox_verdicts"] = {
            name: {
                "category": v.get("category"),
                "malware_names": v.get("malware_names"),
                "confidence": v.get("confidence"),
            }
            for name, v in sv.items()
        }
 
    yara = a.get("crowdsourced_yara_results")
    if yara:
        out["yara"] = [
            {"rule": y.get("rule_name"), "source": y.get("source"), "desc": y.get("description")}
            for y in yara[:8]
        ]
 
    sigma = a.get("sigma_analysis_results")
    if sigma:
        out["sigma_top"] = [
            {"title": s.get("rule_title"), "level": s.get("rule_level")}
            for s in sigma[:8]
        ]
    return out
 
 
# ---------------------------------------------------------------- VirusTotal v2
def vt_v2(h):
    """Fallback verdict via the v2 endpoint (key as query param). Used mainly to
    corroborate; v2 has no pe_info or signature_info."""
    key = env("VT_API_KEY")
    if not key:
        return {"skipped": "no VT_API_KEY set"}
    q = urllib.parse.urlencode({"apikey": key, "resource": h})
    url = f"https://www.virustotal.com/vtapi/v2/file/report?{q}"
    try:
        d = http_json(url)
    except Exception as e:  # noqa: BLE001
        return {"error": err(e)}
    if d.get("response_code") != 1:
        return {"found": False, "note": "hash unknown to VirusTotal (v2)"}
    flagged = {
        eng: s.get("result")
        for eng, s in (d.get("scans") or {}).items()
        if s.get("detected")
    }
    return {
        "found": True,
        "positives": d.get("positives"),
        "total": d.get("total"),
        "scan_date": d.get("scan_date"),
        "sha256": d.get("sha256"),
        "detections": flagged,
    }
 
 
# ---------------------------------------------------------------- MalwareBazaar
def malwarebazaar(h):
    key = env("MB_API_KEY", "ABUSE_CH_API_KEY")
    headers = {"User-Agent": "hashcheck"}
    if key:
        headers["Auth-Key"] = key
    try:
        raw = http(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": h},
            headers=headers,
        )
        d = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        return {"error": err(e)}
 
    status = d.get("query_status")
    if status == "hash_not_found":
        return {"found": False, "note": "hash unknown to MalwareBazaar"}
    if status in ("http_post_expected", "unauthenticated", "no_auth_key"):
        return {"skipped": f"MalwareBazaar auth issue: {status} (set MB_API_KEY)"}
    if status != "ok":
        return {"note": status}
 
    rec = (d.get("data") or [{}])[0]
    signs = []
    for c in (rec.get("code_sign") or []):
        signs.append({
            "subject_cn": c.get("subject_cn"),
            "issuer_cn": c.get("issuer_cn"),
            "valid_from": c.get("valid_from"),
            "valid_to": c.get("valid_to"),
            "thumbprint": c.get("thumbprint"),
        })
    return {
        "found": True,
        "signature": rec.get("signature"),
        "file_type": rec.get("file_type"),
        "file_name": rec.get("file_name"),
        "file_size": rec.get("file_size"),
        "first_seen": rec.get("first_seen"),
        "imphash": rec.get("imphash"),
        "tlsh": rec.get("tlsh"),
        "ssdeep": rec.get("ssdeep"),
        "tags": rec.get("tags"),
        "delivery_method": rec.get("delivery_method"),
        "code_sign": signs,
        "vendor_intel": list((rec.get("vendor_intel") or {}).keys()),
    }
 
 
# --------------------------------------------------------------- Hybrid Analysis
def hybrid_analysis(h):
    key = env("HYBRID_ANALYSIS_KEY", "HA_API_KEY")
    if not key:
        return {"skipped": "no Hybrid Analysis key set"}
    headers = {
        "api-key": key,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }
    q = urllib.parse.urlencode({"hash": h})
    url = f"https://www.hybrid-analysis.com/api/v2/search/hash?{q}"
    try:
        d = http_json(url, headers=headers)
    except Exception as e:  # noqa: BLE001
        return {"error": err(e)}
    if not d:
        return {"found": False, "note": "no Hybrid Analysis report"}
    reports = []
    for r in (d if isinstance(d, list) else [d])[:3]:
        reports.append({
            "verdict": r.get("verdict"),
            "threat_score": r.get("threat_score"),
            "threat_level": r.get("threat_level"),
            "av_detect": r.get("av_detect"),
            "vx_family": r.get("vx_family"),
            "environment": r.get("environment_description"),
            "mitre_attcks": [m.get("technique") for m in (r.get("mitre_attcks") or [])][:8],
        })
    return {"found": True, "reports": reports}
 
 
# ------------------------------------------------------------------- Joe Sandbox
def joe_sandbox(h):
    key = env("JOE_SANDBOX_KEY", "JBX_API_KEY")
    if not key:
        return {"skipped": "no Joe Sandbox key set"}
    base = env("JOE_SANDBOX_URL") or "https://jbxcloud.joesecurity.org/api"
    try:
        s = http_json(f"{base}/v2/analysis/search", data={"apikey": key, "q": h})
    except Exception as e:  # noqa: BLE001
        return {"error": err(e)}
    hits = s.get("data") or []
    if not hits:
        return {"found": False, "note": "no Joe Sandbox analysis"}
    webid = hits[0].get("webid")
    try:
        info = http_json(f"{base}/v2/analysis/info", data={"apikey": key, "webid": webid})
        a = info.get("data", {})
        return {
            "found": True,
            "webid": webid,
            "detection": a.get("detection"),
            "score": a.get("score"),
            "threatname": a.get("threatname"),
        }
    except Exception as e:  # noqa: BLE001
        return {"found": True, "webid": webid, "info_error": err(e)}
 
 
def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: hashcheck.py <hash-or-file>"}))
        sys.exit(2)
 
    kind, val = classify_input(sys.argv[1])
    if kind == "invalid":
        print(json.dumps({
            "error": "input is neither a readable file nor a valid MD5/SHA-1/SHA-256 hash",
            "input": sys.argv[1],
        }))
        sys.exit(2)
 
    result = {"input_kind": kind}
    if kind == "file":
        digests = hash_file(val)
        result["computed"] = digests
        lookup = digests["sha256"]
        result["hash_type"] = "sha256"
    else:
        lookup = val
        result["hash_type"] = HEX_LENGTHS[len(val)]
    result["lookup_hash"] = lookup
 
    # Collect from every source. Each is independent and self-contained.
    result["virustotal"] = vt_v3(lookup)
    if result["virustotal"].get("error") or result["virustotal"].get("skipped"):
        # v3 failed or no key path did not populate; try v2 as a cheap fallback.
        result["virustotal_v2"] = vt_v2(lookup)
    result["malwarebazaar"] = malwarebazaar(lookup)
    result["hybrid_analysis"] = hybrid_analysis(lookup)
    result["joe_sandbox"] = joe_sandbox(lookup)
 
    print(json.dumps(result, indent=2, default=str))
 
 
if __name__ == "__main__":
    main()
