#!/usr/bin/env python3
"""
mcp_dataset.py — build the derived datasets for "The Cost of Being Found".

    python3 mcp_dataset.py -o ~/mcp-paper/data \
        /var/www/requests.log.archive-2026-08 /var/www/requests.log

★ RUN IT NOW, NOT AT THE THREE-MONTH MARK. /var/www/requests.log is TRIMMED TO 30 DAYS by a
weekly cron (added 31 Aug, after admin.php died on a 128MB exhaustion reading 46MB of it).
August — which contains t₀, 12 Aug 2026 17:25 UTC — survives ONLY in
/var/www/requests.log.archive-2026-08. Pass both files, always, and keep the outputs under
version control: they are the only durable record once the live log rolls.

★ WHAT IT EMITS (derived aggregates only — never raw log lines):
    daily_arrivals.csv    date, client, requests, hits_200, first_seen, last_seen
    polling_clients.csv   the persistent monitors: mean req/day, interval, span
    oauth_discovery.csv   who completed the RFC 9728 chain, and how far each got
    conformance.csv       method-level errors observed (-32601, 405 GET-to-POST, 401 dead-ends)
    impersonation.csv     source, distinct vendor identities worn, what it requested
    timeline.csv          one row per day: total, distinct clients, polling share

⚠ PUBLISH THESE, NEVER THE LOG. Raw lines carry OAuth callback URLs with live authorisation
codes, user search text and email-linked sessions. This script emits no paths beyond the MCP
and .well-known surface, no query strings, and no user-agent from a residential source.
⚠ RESIDENTIAL ADDRESSES ARE DROPPED from impersonation.csv. Datacentre addresses are
published routinely by threat-intel feeds; a home broadband address is arguably personal
data, and we have a privacy policy to honour.
⚠ CLASSIFICATION IS BY BEHAVIOUR AND SOURCE, NEVER BY USER-AGENT ALONE — that is the paper's
methods contribution, so the code must embody it rather than merely assert it.
"""
import re, sys, csv, os, collections, datetime, argparse, ipaddress

T0 = datetime.datetime(2026, 8, 12, 17, 25, tzinfo=datetime.timezone.utc)

LINE = re.compile(
    r'^(\S+) \S+ \S+ \[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})[^\]]*\] '
    r'"(\S+) (\S+)[^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"')
MON = {m: i for i, m in enumerate(
    ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], 1)}

# Surfaces this study is about. Everything else is ignored entirely, which is also what
# keeps user search traffic out of the published artefacts.
MCP_PATHS = re.compile(r'^/(mcp|\.well-known/(oauth-protected-resource|oauth-authorization-server|mcp)|llms\.txt|openapi\.json)', re.I)

# Vendor identities that get worn as costumes. Matched against the USER-AGENT ONLY —
# an early version matched the whole line and counted real people arriving with
# utm_source=chatgpt.com in the URL as wearing the ChatGPT identity.
VENDOR_TOKENS = """googlebot chatgpt claude gptbot bingbot amazonbot perplexity applebot
ahrefs meta-external petalbot ccbot semrushbot bytespider yandexbot grok duckassist
google-extended musedirectory mistralai kimi moonshot deepseek chatglm qwen hunyuan
baidu cohere brave you.com""".split()

# Hostile requests. A vendor fetcher does not ask for these. This is the behavioural half
# of the classification: identity says one thing, the request says another.
HOSTILE = re.compile(r'\.env|@fs/|%2e%2e|\.\./|wp-login|\.git/|credentials|\.aws/|'
                     r'phpmyadmin|/shell|xmlrpc\.php|\.claude|\.codex', re.I)

# Datacentre prefixes — impersonation.csv is limited to these. Not exhaustive by design:
# when in doubt a source is treated as residential and dropped, which errs toward privacy.
DC_PREFIX = ('34.','35.','13.','52.','54.','3.','18.','20.','40.','51.1','65.5','104.4',
             '135.','168.6','172.17','45.55','46.101','64.23','67.205','68.183','104.131',
             '128.199','134.122','137.184','138.68','139.59','142.93','143.110','146.190',
             '157.230','159.65','159.89','161.35','164.90','167.71','167.99','178.62',
             '188.166','192.241','206.189','207.154','209.97','5.9.','49.12','65.21',
             '78.46','88.99','91.107','94.130','95.216','116.202','136.243','138.201',
             '142.132','144.76','157.90','159.69','162.55','167.235','168.119','176.9',
             '195.201','51.15','51.19','54.36','54.37','54.38','57.128','92.222','94.23',
             '137.74','141.94','145.239','147.135','149.56','151.80','158.69','164.132',
             '167.114','176.31','188.165','192.95','192.99','198.27','213.186','43.1',
             '49.51','101.32','119.28','124.156','129.226','150.109','170.106','47.',
             # IBM Cloud / SoftLayer — 169.58.147.63 is the most conformant OAuth client
             # observed and was being labelled 'residential', which over-redacts the very
             # row the conformance table needs. Erring toward privacy is right, but a
             # missing prefix costs signal, so add them as they are identified.
             '169.58','169.59','169.44','169.45','169.46','169.47','169.48','158.175',
             '158.176','161.202','119.81','159.122','184.172','173.193','50.22','75.126',
             '23.21','149.28','45.76','108.61','66.42','155.138')

def is_dc(ip):
    return ip.startswith(DC_PREFIX)

def agent_name(ua):
    """Short, stable label for a client. Not trusted — just a handle for grouping."""
    ua = ua.strip()
    if not ua or ua == '-':
        return '(none)'
    m = re.match(r'^([A-Za-z0-9._\-]+)/', ua)
    if m:
        return m.group(1)[:40]
    return ua.split()[0][:40] if ua.split() else '(none)'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-o', '--out', default='./mcp_data')
    ap.add_argument('logs', nargs='+')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    rows = []
    scanned = 0
    for path in a.logs:
        try:
            fh = open(path, errors='replace')
        except OSError as e:
            print(f"  ! skipping {path}: {e}", file=sys.stderr); continue
        for line in fh:
            m = LINE.match(line)
            if not m:
                continue
            scanned += 1
            ip, dd, mon, yy, hh, mi, ss, meth, req, st, sz, ref, ua = m.groups()
            t = datetime.datetime(int(yy), MON.get(mon, 1), int(dd), int(hh), int(mi),
                                  int(ss), tzinfo=datetime.timezone.utc)
            p = req.split('?')[0]
            rows.append(dict(t=t, ip=ip, meth=meth, path=p, raw=req, st=int(st),
                             sz=int(sz) if sz.isdigit() else None,
                             ua=ua, name=agent_name(ua)))
    if not rows:
        sys.exit("no parsable lines")

    mcp = [r for r in rows if MCP_PATHS.match(r['path'])]
    days = sorted({r['t'].date() for r in mcp})
    print(f"{scanned:,} lines scanned · {len(mcp):,} on the MCP/discovery surface · "
          f"{days[0]} → {days[-1]} ({(days[-1]-days[0]).days+1} days)")
    print(f"t0 = {T0.date()} — {sum(1 for r in mcp if r['t'] < T0)} requests BEFORE listing, "
          f"{sum(1 for r in mcp if r['t'] >= T0)} after")

    # ── daily_arrivals ──────────────────────────────────────────────────────
    per = collections.defaultdict(lambda: dict(n=0, ok=0, first=None, last=None))
    for r in mcp:
        k = (r['t'].date(), r['name'])
        d = per[k]; d['n'] += 1
        if r['st'] in (200, 202): d['ok'] += 1
        if d['first'] is None or r['t'] < d['first']: d['first'] = r['t']
        if d['last'] is None or r['t'] > d['last']: d['last'] = r['t']
    with open(f"{a.out}/daily_arrivals.csv", 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['date','client','requests','ok_2xx','first_seen_utc','last_seen_utc','days_since_t0'])
        for (day, name), d in sorted(per.items()):
            w.writerow([day, name, d['n'], d['ok'], d['first'].strftime('%H:%M:%S'),
                        d['last'].strftime('%H:%M:%S'), (day - T0.date()).days])

    # ── polling_clients — the tax, which is the paper's centre ──────────────
    by_client = collections.defaultdict(list)
    for r in mcp:
        by_client[r['name']].append(r)
    with open(f"{a.out}/polling_clients.csv", 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['client','total_requests','active_days','mean_req_per_active_day',
                    'median_interval_s','first_seen','last_seen','distinct_ips','methods','status_codes'])
        for name, rs in sorted(by_client.items(), key=lambda kv: -len(kv[1])):
            if len(rs) < 20:
                continue
            ts = sorted(r['t'] for r in rs)
            gaps = sorted((ts[i+1]-ts[i]).total_seconds() for i in range(len(ts)-1))
            med = gaps[len(gaps)//2] if gaps else 0
            dcount = len({t.date() for t in ts})
            w.writerow([name, len(rs), dcount, round(len(rs)/dcount, 1), round(med, 1),
                        ts[0].date(), ts[-1].date(), len({r['ip'] for r in rs}),
                        '|'.join(sorted({r['meth'] for r in rs})),
                        '|'.join(f"{c}:{n}" for c, n in
                                 sorted(collections.Counter(r['st'] for r in rs).items()))])

    # ── oauth_discovery — RFC 9728 chain completion, per source ─────────────
    STEPS = [('protected_resource', r'/\.well-known/oauth-protected-resource'),
             ('auth_server',        r'/\.well-known/oauth-authorization-server'),
             ('path_suffixed',      r'/\.well-known/oauth-[a-z-]+/mcp'),
             ('mcp_retry',          r'^/mcp$')]
    disc = collections.defaultdict(lambda: collections.Counter())
    for r in mcp:
        for label, rx in STEPS:
            if re.search(rx, r['path']):
                disc[(r['ip'], r['name'])][label] += 1
        if r['path'] == '/mcp' and r['st'] == 401:
            disc[(r['ip'], r['name'])]['got_401'] += 1
    with open(f"{a.out}/oauth_discovery.csv", 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['source','client','got_401','protected_resource','auth_server',
                    'path_suffixed','mcp_retry','completed_chain'])
        for (ip, name), c in sorted(disc.items(), key=lambda kv: -sum(kv[1].values())):
            if not c['got_401'] and not c['protected_resource']:
                continue
            done = bool(c['protected_resource'] and c['auth_server'] and c['mcp_retry'])
            w.writerow([ip if is_dc(ip) else 'residential', name, c['got_401'],
                        c['protected_resource'], c['auth_server'], c['path_suffixed'],
                        c['mcp_retry'], int(done)])

    # ── conformance — client-side failure modes ────────────────────────────
    with open(f"{a.out}/conformance.csv", 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['failure_mode','client','occurrences','note'])
        get_to_post = collections.Counter(r['name'] for r in mcp
                                          if r['path'] == '/mcp' and r['meth'] == 'GET')
        for name, n in get_to_post.most_common():
            w.writerow(['GET_to_POST_only_endpoint', name, n, 'expects 405'])
        dead = collections.Counter()
        for (ip, name), c in disc.items():
            if c['got_401'] and not c['protected_resource']:
                dead[name] += c['got_401']
        for name, n in dead.most_common():
            w.writerow(['401_dead_end_no_discovery', name, n, 'never fetched metadata'])

    # ── impersonation — the methods contribution ───────────────────────────
    worn = collections.defaultdict(set)
    hostile = collections.Counter()
    allreq = collections.Counter()
    for r in rows:                      # whole log, not just the MCP surface
        low = r['ua'].lower()
        hit = [t for t in VENDOR_TOKENS if t in low]
        if hit:
            worn[r['ip']].update(hit)
        if HOSTILE.search(r['raw']):
            hostile[r['ip']] += 1
        allreq[r['ip']] += 1
    with open(f"{a.out}/impersonation.csv", 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['source','datacentre','distinct_vendor_identities','identities',
                    'total_requests','hostile_requests'])
        for ip, v in sorted(worn.items(), key=lambda kv: -len(kv[1])):
            if len(v) < 2:
                continue
            if not is_dc(ip):           # ⚠ residential sources are NOT published
                continue
            w.writerow([ip, 1, len(v), '|'.join(sorted(v)), allreq[ip], hostile[ip]])

    # ── client_classes — BEHAVIOURAL classification, not volume ────────────
    # ⚠ WHY THIS REPLACED A VOLUME HEURISTIC. The first version labelled a client
    # "polling" if it made >=20 requests over >=5 days — which is close to circular:
    # frequent clients were called monitors because they were frequent. The 97-99%
    # figure cannot rest on that. Classification is now by OBSERVABLE BEHAVIOUR:
    #
    #   MONITOR      never touched anything but /mcp and /.well-known/*, recurring on
    #                >=5 days, and NEVER received a response large enough to be a tool
    #                result. Cannot have invoked a tool.
    #   PROBE        one or two visits, discovery surface only, not recurring.
    #   CONFORMANT   completed the RFC 9728 chain (metadata + retry).
    #   MIXED        also requested product pages — behaves like a crawler, not a client.
    #
    # ⚠ THE SIZE PROXY AND ITS LIMIT. The access log records response BYTES, not the
    # JSON-RPC method: an `initialize` reply is ~350 bytes here and a `tools/list`
    # manifest ~2.8 kB, while any real tool result is larger because it carries
    # availability rows. So "never exceeded TOOL_RESULT_MIN bytes" is EVIDENCE OF
    # ABSENCE OF TOOL USE, not proof — state it that way in the paper. It is also
    # corroborated: tool invocation requires auth, and these clients never authenticate.
    TOOL_RESULT_MIN = 4096
    # ⚠ DOCUMENTATION IS NOT THE PRODUCT. A first version disqualified any client that
    # requested a non-MCP path, which pushed the two largest clients into MIXED and
    # collapsed the monitoring share from ~97% to ~33%. That was wrong: a directory scout
    # that reads the API documentation and then health-checks /mcp every fifteen minutes —
    # which is exactly what one observed directory does, and documents publicly — is a
    # MONITOR. Reading the docs is part of screening, not crawling.
    # What genuinely distinguishes a crawler is requesting the PRODUCT surface: the search
    # interface and the per-route content pages that a general web crawler harvests.
    DOCS = re.compile(r'^/(api\.html|for-businesses\.html|terms\.html|faq\.html|'
                      r'how-it-works\.html|privacy-policy\.html|robots\.txt|sitemap|'
                      r'favicon|apple-touch-icon|og-image|\.well-known/|$)', re.I)
    prod = collections.defaultdict(int)   # PRODUCT-surface requests only
    docs = collections.defaultdict(int)   # documentation/discovery, allowed for a monitor
    for r in rows:
        if MCP_PATHS.match(r['path']):
            continue
        if DOCS.match(r['path']):
            docs[r['ip']] += 1
        else:
            prod[r['ip']] += 1
    with open(f"{a.out}/client_classes.csv", 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['client','class','total_requests','active_days','mean_per_day',
                    'max_response_bytes','median_response_bytes','could_have_invoked_tool',
                    'touched_product_pages','read_docs','completed_oauth_chain'])
        chain_clients = {name for (ip, name), c in disc.items()
                         if c['protected_resource'] and c['auth_server'] and c['mcp_retry']}
        for name, rs in sorted(by_client.items(), key=lambda kv: -len(kv[1])):
            if len(rs) < 10:
                continue
            sizes = sorted(r['sz'] for r in rs if r['sz'] is not None)
            mx = sizes[-1] if sizes else 0
            md = sizes[len(sizes)//2] if sizes else 0
            dcount = len({r['t'].date() for r in rs})
            touched = any(prod.get(r['ip'], 0) for r in rs)
            could = mx >= TOOL_RESULT_MIN
            if touched:
                cls = 'MIXED'
            elif name in chain_clients:
                cls = 'CONFORMANT'
            elif dcount >= 5 and not could:
                cls = 'MONITOR'
            else:
                cls = 'PROBE'
            read_docs = any(docs.get(r['ip'], 0) for r in rs)
            w.writerow([name, cls, len(rs), dcount, round(len(rs)/dcount, 1), mx, md,
                        int(could), int(touched), int(read_docs),
                        int(name in chain_clients)])

    # ── baseline + opt-out: the two small controlled comparisons ───────────
    with open(f"{a.out}/controls.csv", 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['comparison','window','days','requests','req_per_day','note'])
        pre = [r for r in mcp if r['t'] < T0]
        post = [r for r in mcp if r['t'] >= T0]
        pre_days = len({r['t'].date() for r in pre}) or 1
        post_days = len({r['t'].date() for r in post}) or 1
        w.writerow(['pre_listing_baseline', f"..{T0.date()}", pre_days, len(pre),
                    round(len(pre)/pre_days, 2), 'endpoint did not exist; 404s only'])
        w.writerow(['post_listing', f"{T0.date()}..", post_days, len(post),
                    round(len(post)/post_days, 2), 'single intervention, no other submission'])
        # ⚠ OPT-OUT AS A SMALL CONTROLLED EXPERIMENT. One monitor declared in its own
        # user-agent that it never invokes tools and honoured a published opt-out. The
        # before/after rate turns a qualitative note into a measurement — name the client
        # with --optout to emit it.
        oc = os.environ.get('OPTOUT_CLIENT')
        od = os.environ.get('OPTOUT_DATE')
        if oc and od:
            cut = datetime.date.fromisoformat(od)
            rs = by_client.get(oc, [])
            for label, sel in (('optout_before', lambda d: d < cut), ('optout_after', lambda d: d >= cut)):
                sub = [r for r in rs if sel(r['t'].date())]
                dd = len({r['t'].date() for r in sub}) or 1
                w.writerow([label, oc, dd, len(sub), round(len(sub)/dd, 2), f'cutover {od}'])

    # ── timeline — one row per day ─────────────────────────────────────────
    with open(f"{a.out}/timeline.csv", 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['date','days_since_t0','requests','distinct_clients','distinct_sources',
                    'polling_share_pct'])
        # Behavioural, matching client_classes.csv — NOT a volume heuristic.
        heavy = set()
        for n, rs in by_client.items():
            if len(rs) < 10: continue
            szs = [r['sz'] for r in rs if r['sz'] is not None]
            if len({r['t'].date() for r in rs}) >= 5 and (max(szs) if szs else 0) < 4096 \
               and not any(prod.get(r['ip'], 0) for r in rs):
                heavy.add(n)
        for day in days:
            d = [r for r in mcp if r['t'].date() == day]
            pol = sum(1 for r in d if r['name'] in heavy)
            w.writerow([day, (day - T0.date()).days, len(d),
                        len({r['name'] for r in d}), len({r['ip'] for r in d}),
                        round(100*pol/len(d), 1) if d else 0])

    print(f"\nwritten to {a.out}/:")
    for fn in ('timeline.csv','client_classes.csv','controls.csv','polling_clients.csv','daily_arrivals.csv',
               'oauth_discovery.csv','conformance.csv','impersonation.csv'):
        p = f"{a.out}/{fn}"
        if os.path.exists(p):
            print(f"   {fn:<24}{sum(1 for _ in open(p))-1:>6} rows")
    print("""
⚠ REVIEW impersonation.csv BEFORE PUBLISHING. Residential sources are already dropped, but
  read it once: a misclassified prefix would publish a home address.
⚠ KEEP THESE UNDER VERSION CONTROL. requests.log is trimmed to 30 days; once August rolls
  out of the archive these CSVs are the only record of t0 and the first fortnight.
⚠ RE-RUN WEEKLY and commit. The series is the asset; a snapshot is not.
""")

if __name__ == '__main__':
    main()
