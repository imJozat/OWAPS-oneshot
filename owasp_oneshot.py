cat > owasp_oneshot.py <<'PY'
#!/usr/bin/env python3
# OWASP-OneShot: Low-impact web tester for Termux
# Use only with explicit permission.

import argparse, re, time, json, os, sys, hashlib, urllib.parse, urllib.request
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

USER_AGENT = "OWASP-OneShot/1.0 (+safe; termux; python3)"
SQL_ERRORS = [
    "you have an error in your sql syntax","warning: mysql","unclosed quotation mark",
    "quoted string not properly terminated","sqlstate[","odbc sql server driver",
    "sql syntax near","ORA-00933","ORA-01756","SQLite3::SQLException","PG::SyntaxError"
]
SEC_HEADERS = [
    "content-security-policy","x-frame-options","x-content-type-options",
    "referrer-policy","permissions-policy","strict-transport-security"
]
DEFAULT_WORDLIST = ["admin","admin/","login","login/","dashboard","config","config/",
                    ".git/",".env","robots.txt","sitemap.xml","server-status","phpinfo.php",
                    "backup","backup.zip","old","test","staging","api","api/","graphql"]

@dataclass
class Finding:
    owasp: str; title: str; severity: str; evidence: str; url: str
    parameter: str = ""; recommendation: str = ""

def urljoin(b, l): return urllib.parse.urljoin(b, l)
def same_host(a,b):
    try:
        A = urllib.parse.urlparse(a).netloc.split(":")[0].lower()
        B = urllib.parse.urlparse(b).netloc.split(":")[0].lower()
        return A and A==B
    except: return False

def fetch(url, method="GET", data=None, headers=None, timeout=10):
    h = {"User-Agent": USER_AGENT, "Accept":"*/*"}
    if headers: h.update(headers)
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        h["Content-Type"]="application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), dict(r.getheaders()), r.read()
    except urllib.error.HTTPError as e:
        try: body = e.read()
        except: body = b""
        return e.code, dict(e.headers), body
    except Exception:
        return None, {}, b""

def extract_links(url, body):
    out=set()
    try: txt = body.decode(errors="ignore")
    except: return out
    if BeautifulSoup:
        soup=BeautifulSoup(txt,"html.parser")
        for a in soup.find_all("a", href=True): out.add(urljoin(url,a["href"]))
        for tag in soup.find_all(src=True): out.add(urljoin(url, tag.get("src")))
    else:
        for m in re.finditer(r'href=["\']([^"\']+)["\']', txt, re.I):
            out.add(urljoin(url, m.group(1)))
    return out

def check_headers(url, headers):
    res=[]; h={k.lower():v for k,v in headers.items()}
    for sh in SEC_HEADERS:
        if sh not in h:
            res.append(Finding("A05: Security Misconfiguration",
                               f"Missing security header: {sh}","Medium",
                               f"{sh} absent in response.","{0}".format(url),
                               recommendation=f"Add `{sh}` with safe baseline."))
    cookie = h.get("set-cookie","")
    if cookie:
        cl=cookie.lower()
        if "httponly" not in cl:
            res.append(Finding("A02: Cryptographic Failures","Cookies missing HttpOnly","Medium",
                               "Set-Cookie without HttpOnly.",url,recommendation="Add HttpOnly to sensitive cookies."))
        if url.startswith("https") and "secure" not in cl:
            res.append(Finding("A02: Cryptographic Failures","Cookies missing Secure flag","Medium",
                               "Secure flag absent over HTTPS.",url,recommendation="Add Secure for HTTPS cookies."))
        if "samesite" not in cl:
            res.append(Finding("A02: Cryptographic Failures","Cookies missing SameSite","Low",
                               "SameSite not set.",url,recommendation="Use SameSite=Lax/Strict."))
    return res

def test_directory_listing(base):
    res=[]
    probe=base.rstrip("/")
    code,_,body=fetch(probe)
    if code==200 and b"Index of /" in body:
        res.append(Finding("A05: Security Misconfiguration","Directory listing enabled","Medium",
                           "Found 'Index of /' in response.",probe,
                           recommendation="Disable autoindex/directory listing."))
    return res

def brute_paths(base, words):
    res=[]
    for w in words:
        p = urljoin(base if base.endswith("/") else base+"/", w)
        code,_,_ = fetch(p)
        if code in (200,401,403):
            res.append(Finding("A05: Security Misconfiguration",f"Interesting path: {w}","Info",
                               f"HTTP {code} on {p}",p,recommendation="Review/restrict if unnecessary."))
        time.sleep(0.05)
    return res

def reflect_check(body, token):
    try: return token in body.decode(errors="ignore")
    except: return False

def test_xss(url):
    res=[]; P=urllib.parse.urlparse(url); qs=urllib.parse.parse_qs(P.query, keep_blank_values=True)
    if not qs: return res
    token="ONESHOTXSS"+hashlib.md5(url.encode()).hexdigest()[:6]
    payload=f"{token}<svg/onload=alert(1)>"
    for k in qs:
        altered=dict(qs); altered[k]=[payload]
        new_qs=urllib.parse.urlencode({kk:vv[0] for kk,vv in altered.items()})
        new_url=urllib.parse.urlunparse(P._replace(query=new_qs))
        code,_,body=fetch(new_url)
        if code and code<500 and reflect_check(body, token):
            res.append(Finding("A03: Injection","Reflected XSS indicator","High",
                               f"Token reflected at param '{k}'. Evidence: {token}",new_url,k,
                               recommendation="Output encode + CSP + input validation."))
        time.sleep(0.05)
    return res

def test_sqli(url):
    res=[]; P=urllib.parse.urlparse(url); qs=urllib.parse.parse_qs(P.query, keep_blank_values=True)
    if not qs: return res
    for k in qs:
        altered=dict(qs); altered[k]=[(qs[k][0] if qs[k] else "")+"'"]
        new_qs=urllib.parse.urlencode({kk:vv[0] for kk,vv in altered.items()})
        new_url=urllib.parse.urlunparse(P._replace(query=new_qs))
        code,_,body=fetch(new_url)
        txt=body.decode(errors="ignore").lower()
        if any(e in txt for e in SQL_ERRORS):
            res.append(Finding("A03: Injection","SQL error-based indicator","High",
                               f"SQL error after single-quote on '{k}'.",new_url,k,
                               recommendation="Use parameterized queries/ORM."))
        time.sleep(0.05)
    return res

def test_open_redirect(url):
    res=[]; P=urllib.parse.urlparse(url); qs=urllib.parse.parse_qs(P.query, keep_blank_values=True)
    red = [p for p in qs if p.lower() in ("next","url","target","redirect","redir","dest","destination","return","continue")]
    if not red: return res
    evil="https://example.org/oneshot"
    for k in red:
        altered=dict(qs); altered[k]=[evil]
        new_qs=urllib.parse.urlencode({kk:vv[0] for kk,vv in altered.items()})
        new_url=urllib.parse.urlunparse(P._replace(query=new_qs))
        code,headers,_=fetch(new_url)
        loc=headers.get("Location") or headers.get("location")
        if code in (301,302,303,307,308) and loc and "example.org/oneshot" in loc:
            res.append(Finding("A01: Broken Access Control","Open redirect via query param","Medium",
                               f"Param '{k}' redirected to external domain.",new_url,k,
                               recommendation="Allowlist redirect targets or use relative paths."))
    return res

def test_idor(url):
    res=[]; P=urllib.parse.urlparse(url); qs=urllib.parse.parse_qs(P.query, keep_blank_values=True)
    cand=[(k,v[0]) for k,v in qs.items() if v and re.fullmatch(r"\\d+", v[0])]
    for k,v in cand:
        for n in [str(int(v)+1), str(max(int(v)-1,0))]:
            altered=dict(qs); altered[k]=[n]
            new_qs=urllib.parse.urlencode({kk:vv[0] for kk,vv in altered.items()})
            new_url=urllib.parse.urlunparse(P._replace(query=new_qs))
            code,_,_=fetch(new_url)
            if code==200 and n!=v:
                res.append(Finding("A01: Broken Access Control","Potential IDOR (numeric)","Medium",
                                   f"Changed '{k}' {v}→{n} and still 200.",new_url,k,
                                   recommendation="Enforce object-level authorization."))
            time.sleep(0.05)
    return res

def check_https_hsts(url, headers):
    res=[]; low={k.lower():v for k,v in headers.items()}
    if url.startswith("https://") and "strict-transport-security" not in low:
        res.append(Finding("A02: Cryptographic Failures","Missing HSTS on HTTPS","Low",
                           "No Strict-Transport-Security header.",url,
                           recommendation="Add HSTS with safe max-age + preload if suitable."))
    return res

def crawl(start, max_pages=40):
    seen=set(); q=deque([start]); pages=[]
    while q and len(pages)<max_pages:
        u=q.popleft()
        if u in seen: continue
        seen.add(u)
        code,h,b=fetch(u)
        if not code: continue
        pages.append((u,code,h,b))
        for l in extract_links(u,b):
            if same_host(start,l) and l not in seen and len(pages)+len(q)<max_pages:
                q.append(l)
    return pages

def analyze(start, max_pages=40):
    pages=crawl(start,max_pages)
    findings=[]
    for (url,code,headers,body) in pages:
        findings.extend(check_headers(url, headers))
        findings.extend(check_https_hsts(url, headers))
        findings.extend(test_directory_listing(url))
        findings.extend(brute_paths(url, DEFAULT_WORDLIST[:15]))
        findings.extend(test_xss(url))
        findings.extend(test_sqli(url))
        findings.extend(test_open_redirect(url))
        findings.extend(test_idor(url))
    # de-dup
    uniq=[]; S=set()
    for f in findings:
        k=(f.owasp,f.title,f.url,f.parameter)
        if k not in S: S.add(k); uniq.append(f)
    return pages, uniq

def write_reports(target, pages, findings, outdir):
    os.makedirs(outdir, exist_ok=True)
    ts=time.strftime("%Y%m%d-%H%M%S"); base=os.path.join(outdir,f"oneshot_{ts}")
    md, js = base+".md", base+".json"
    by=defaultdict(list)
    for f in findings: by[f.owasp].append(f)
    sev={"High":0,"Medium":0,"Low":0,"Info":0}
    for f in findings: sev[f.severity]=sev.get(f.severity,0)+1
    L=[]
    L.append(f"# OWASP-OneShot Report for {target}\\n")
    L.append(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\\n- Pages crawled: {len(pages)}\\n")
    L.append("## Summary by Severity")
    for s in ["High","Medium","Low","Info"]:
        L.append(f"- **{s}**: {sev.get(s,0)}")
    L.append("\\n## Findings (OWASP Top 10 - 2021)")
    for cat in sorted(by.keys()):
        L.append(f\"### {cat}\")
        for f in by[cat]:
            L.append(f\"- **{f.title}** ({f.severity})\\n  - URL: `{f.url}`\" + (f\"\\n  - Parameter: `{f.parameter}`\" if f.parameter else \"\") + f\"\\n  - Evidence: {f.evidence}\" + (f\"\\n  - Recommendation: {f.recommendation}\" if f.recommendation else \"\")) 
        L.append(\"\")
    L.append(\"## Crawl Coverage (sample)\")
    for u,c,_,_ in pages[:20]: L.append(f\"- {c} {u}\")
    open(md,\"w\",encoding=\"utf-8\").write(\"\\n\".join(L))
    open(js,\"w\",encoding=\"utf-8\").write(json.dumps({\"target\":target,\"pages_crawled\":len(pages),\"findings\":[asdict(f) for f in findings]}, indent=2))
    return md, js

def main():
    ap=argparse.ArgumentParser(description=\"OWASP-OneShot (safe, low-impact web tester)\")
    ap.add_argument(\"url\", help=\"Start URL (http/https)\")
    ap.add_argument(\"--max-pages\", type=int, default=40)
    ap.add_argument(\"--out\", default=\"./reports\")
    a=ap.parse_args()
    if not (a.url.startswith(\"http://\") or a.url.startswith(\"https://\")):
        print(\"Please include http:// or https:// in URL\"); sys.exit(1)
    pages,findings=analyze(a.url, max_pages=a.max_pages)
    md,js=write_reports(a.url, pages, findings, a.out)
    print(\"Report (MD):\", md); print(\"Report (JSON):\", js)
    print(\"Use responsibly. Only with permission.\")

if __name__==\"__main__\": main()
PY
