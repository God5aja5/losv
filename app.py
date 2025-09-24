import os
import time
import json
import urllib.parse
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, make_response, abort

app = Flask(__name__)

# =========================
# Config
# =========================
CARS24_AUTH = os.getenv("CARS24_AUTH", "Basic YzJiX2Zyb250ZW5kOko1SXRmQTk2bTJfY3lRVk00dEtOSnBYaFJ0c0NtY1h1")
CARS24_API_VERSION = os.getenv("CARS24_API_VERSION", datetime.now(timezone.utc).strftime("%Y-%m"))
UPSTREAM_TIMEOUT = int(os.getenv("UPSTREAM_TIMEOUT", "12"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "600"))  # 10 min
MAX_LOG_SIZE = int(os.getenv("MAX_LOG_SIZE", "5000"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()  # optional token to protect /admin

UPSTREAM_HEADERS = {
    "authority": "vehicle.cars24.team",
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-US,en;q=0.9",
    "authorization": CARS24_AUTH,
    "device_category": "mSite",
    "origin": "https://www.cars24.com",
    "origin_source": "c2b-website",
    "platform": "rto",
    "referer": "https://www.cars24.com/",
    "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
}

# =========================
# In-memory stores
# =========================
REQUEST_LOG = []  # list of dicts
BANNED_IPS = set()  # banned IPs
IP_LIMITS = {}  # ip -> int (daily limit)
GLOBAL_DAILY_LIMIT = None  # or int

CACHE = {}  # vnum -> (epoch_ts, json)

# =========================
# Helpers
# =========================
def now_utc():
    return datetime.now(timezone.utc)

def now_str():
    return now_utc().strftime("%Y-%m-%d %H:%M:%S")

def today_str():
    return now_utc().strftime("%Y-%m-%d")

def month_str(dt=None):
    dt = dt or now_utc()
    return dt.strftime("%Y-%m")

def get_client_ip():
    # Respect Vercel's X-Forwarded-For
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def log_request(entry):
    REQUEST_LOG.append(entry)
    # Prevent unbounded growth
    if len(REQUEST_LOG) > MAX_LOG_SIZE:
        del REQUEST_LOG[: len(REQUEST_LOG) - MAX_LOG_SIZE]

def is_admin_allowed():
    if not ADMIN_TOKEN:
        return True  # unprotected if no token set
    token = request.args.get("token") or request.form.get("token") or request.cookies.get("admin_token")
    return token == ADMIN_TOKEN

def redirect_to_admin():
    base = url_for("admin_dashboard")
    if ADMIN_TOKEN:
        # Keep token across redirects via query param
        base += f"?token={ADMIN_TOKEN}"
    return redirect(base)

def set_admin_cookie(resp):
    if ADMIN_TOKEN:
        resp.set_cookie("admin_token", ADMIN_TOKEN, max_age=7*24*3600, httponly=True, samesite="Lax")
    return resp

def get_daily_count_for_ip(ip, day=None):
    day = day or today_str()
    return sum(1 for r in REQUEST_LOG if (r.get("ip") == ip and r.get("ts", "").startswith(day) and not r.get("admin")))

def get_limit_for_ip(ip):
    return IP_LIMITS.get(ip, GLOBAL_DAILY_LIMIT)

def check_ban_and_limit(ip):
    if ip in BANNED_IPS:
        return False, "IP banned."
    limit = get_limit_for_ip(ip)
    if limit is not None:
        used = get_daily_count_for_ip(ip)
        if used >= limit:
            return False, f"Daily limit reached ({limit})."
    return True, None

def cache_get(vnum):
    entry = CACHE.get(vnum)
    if not entry:
        return None
    ts, data = entry
    if time.time() - ts > CACHE_TTL_SECONDS:
        del CACHE[vnum]
        return None
    return data

def cache_set(vnum, data):
    CACHE[vnum] = (time.time(), data)

# =========================
# Upstream fetch
# =========================
import requests

def fetch_vehicle(vnum):
    vnum = (vnum or "").strip().upper().replace(" ", "")
    if not vnum:
        return {"error": "Missing vehicle number"}, 400, False

    cached = cache_get(vnum)
    if cached:
        return cached, 200, True

    version = CARS24_API_VERSION or datetime.now(timezone.utc).strftime("%Y-%m")
    url = f"https://vehicle.cars24.team/v1/{version}/vehicle-number/{urllib.parse.quote(vnum)}"
    try:
        r = requests.get(url, headers=UPSTREAM_HEADERS, timeout=UPSTREAM_TIMEOUT)
        # Sometimes upstream returns non-200 with JSON errors
        data = r.json() if r.content else {"error": "Empty response"}
        if r.status_code == 200:
            cache_set(vnum, data)
        return data, r.status_code, False
    except requests.exceptions.JSONDecodeError:
        return {"error": "Failed to parse upstream JSON."}, 502, False
    except requests.exceptions.Timeout:
        return {"error": "Upstream timeout."}, 504, False
    except Exception as e:
        return {"error": f"Upstream error: {str(e)}"}, 502, False

# =========================
# UI templates
# =========================
BASE_HEAD = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{{ title }}</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🚗</text></svg>">
<style>
  .kv { @apply grid grid-cols-1 sm:grid-cols-2 gap-2; }
  .badge { @apply inline-block rounded px-2 py-0.5 text-xs font-semibold; }
  .badge-green { @apply bg-green-100 text-green-700; }
  .badge-red { @apply bg-red-100 text-red-700; }
  .badge-gray { @apply bg-gray-100 text-gray-700; }
  .chip { @apply inline-flex items-center gap-1 rounded-full bg-gray-100 px-3 py-1 text-sm; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  details > summary { cursor: pointer; }
</style>
</head>
<body class="bg-slate-50 text-slate-900">
<header class="bg-white border-b">
  <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
    <a href="/" class="font-bold text-lg">Vehicle Lookup</a>
    <nav class="flex items-center gap-4 text-sm">
      <a class="text-blue-600 hover:underline" href="/vehicle/formatted">Formatted</a>
      <a class="text-blue-600 hover:underline" href="/vehicle/json">JSON</a>
      <a class="text-blue-600 hover:underline" href="/admin{{ '?token=' + token if token else '' }}">Admin</a>
    </nav>
  </div>
</header>
<main class="max-w-6xl mx-auto px-4 py-6">
"""

BASE_FOOT = """
</main>
<footer class="max-w-6xl mx-auto px-4 py-10 text-xs text-gray-500">
  <p>
    Note: Stats are in-memory. On serverless cold starts or scale-out, they reset. For persistence, use a datastore (e.g., Upstash Redis).
  </p>
</footer>
</body></html>
"""

HOME_HTML = BASE_HEAD + """
<div class="bg-white shadow-sm rounded-lg p-6">
  <h1 class="text-2xl font-semibold mb-2">Vehicle Lookup API</h1>
  <p class="text-gray-600 mb-6">Enter a registration number to fetch details via Cars24 upstream.</p>
  <form action="/vehicle/formatted" method="get" class="flex flex-col sm:flex-row gap-3">
    <input name="vnum" placeholder="e.g., UK04AP2300" class="flex-1 border rounded px-4 py-2" />
    <button class="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700">View Formatted</button>
    <a class="px-4 py-2 rounded border hover:bg-gray-50" href="#" onclick="const v=document.querySelector('input[name=vnum]').value; if(v){window.location='/vehicle/json?vnum='+encodeURIComponent(v)}; return false;">View JSON</a>
  </form>

  <div class="mt-8">
    <h2 class="font-semibold mb-2">Endpoints</h2>
    <ul class="list-disc pl-5 space-y-1 text-sm">
      <li><span class="mono">GET /vehicle/json?vnum=UK04AP2300</span></li>
      <li><span class="mono">GET /vehicle/json/vnum=UK04AP2300</span></li>
      <li><span class="mono">GET /vehicle/formatted?vnum=UK04AP2300</span></li>
      <li><span class="mono">GET /vehicle/formatted/vnum=UK04AP2300</span></li>
      <li><span class="mono">GET /admin</span> – dashboard, bans, limits, logs</li>
    </ul>
  </div>
</div>
""" + BASE_FOOT

def render_detail_html(vnum, data, cached=False):
    detail = (data or {}).get("detail", {})
    success = bool((data or {}).get("success"))
    img_url = detail.get("modelImageUrl") or ""
    reg_num = detail.get("registrationNumber") or vnum

    # Important keys first for nicer display
    important_keys = [
        "registeredPlace","pucUpTo","rcStatus","unladenWt","hypothecation","financier",
        "vehicleCategory","fuelType","rawFuelType","registeredAt","color","rcNormsDesc",
        "engineNo","chassisNo","chassisNoFull","insuranceCompany","insuranceUpTo","rtoNocIssued",
        "manufacturingMonthYr","fitnessUpTo","taxUpTo","vehicleClassDesc","registrationNumber",
        "modelImageUrl","seatCap","insurancePolicyNo","isCommercial","isCommercialFrachiseRegion",
        "updatedAt","BRAND","MODEL","YEAR","STATES","RTO","rc_model","full_details",
        "rc_owner_name","rc_owner_name_masked","rc_vh_class_desc","rc_owner_sr","DS_DETAILS"
    ]
    # Build ordered items
    keys = list(detail.keys())
    ordered = [k for k in important_keys if k in detail] + [k for k in keys if k not in important_keys]

    def esc(s):
        try:
            return str(s)
        except Exception:
            return repr(s)

    def render_value(val, level=0):
        pad = " " * (level * 2)
        if isinstance(val, dict):
            parts = []
            for k, v in val.items():
                parts.append(f'<div class="ml-{level*2}"><span class="font-medium">🔹 {esc(k)}:</span> {"" if isinstance(v,(dict,list)) else esc(v)}</div>')
                if isinstance(v, (dict, list)):
                    parts.append(render_value(v, level+2))
            return "\n".join(parts)
        elif isinstance(val, list):
            parts = []
            for i, item in enumerate(val, 1):
                parts.append(f'<div class="ml-{level*2}">📌 Item {i}:</div>')
                parts.append(render_value(item, level+2))
            return "\n".join(parts)
        else:
            return f'<div class="ml-{level*2}">{esc(val)}</div>'

    # Top summary chips
    chips = []
    if detail.get("vehicleClassDesc"): chips.append(f'<span class="chip">🚘 {esc(detail["vehicleClassDesc"])}</span>')
    if detail.get("fuelType"): chips.append(f'<span class="chip">⛽ {esc(detail["fuelType"])}</span>')
    if detail.get("rcStatus"): chips.append(f'<span class="chip">📄 {esc(detail["rcStatus"])}</span>')
    if detail.get("color"): chips.append(f'<span class="chip">🎨 {esc(detail["color"])}</span>')
    if detail.get("registeredPlace"): chips.append(f'<span class="chip">📍 {esc(detail["registeredPlace"])}</span>')

    body = []
    for k in ordered:
        v = detail.get(k)
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            body.append(f'<h3 class="text-lg font-semibold mt-6 mb-2">{esc(k).upper()}</h3>')
            body.append('<div class="space-y-1">' + render_value(v, 1) + "</div>")
        else:
            body.append(f'<div class="grid grid-cols-1 sm:grid-cols-3 gap-2 items-center border-b py-2"><div class="text-gray-500">🔹 {esc(k)}</div><div class="sm:col-span-2">{esc(v)}</div></div>')

    cached_badge = '<span class="badge badge-gray">cache</span>' if cached else ''
    ok_badge = '<span class="badge badge-green">success</span>' if success else '<span class="badge badge-red">failed</span>'

    html = BASE_HEAD + f"""
<div class="bg-white shadow-sm rounded-lg p-6">
  <div class="flex items-start gap-4">
    <div class="flex-1">
      <h1 class="text-2xl font-semibold">📝 Vehicle Details for <span class="mono">{esc(reg_num)}</span> {ok_badge} {cached_badge}</h1>
      <div class="mt-3 flex flex-wrap gap-2">{''.join(chips)}</div>
    </div>
    <div class="w-40 h-28 shrink-0 rounded border bg-white flex items-center justify-center overflow-hidden">
      {"<img src='%s' class='max-w-full max-h-full' alt='car' />" % img_url if img_url else "<div class='text-gray-400 text-sm'>No image</div>"}
    </div>
  </div>
  <div class="mt-6">
    {''.join(body) if body else "<div class='text-gray-500'>No details found.</div>"}
  </div>

  <details class="mt-8">
    <summary class="font-medium">Raw JSON</summary>
    <pre class="mt-2 p-3 bg-gray-50 border rounded overflow-x-auto text-xs mono">{json.dumps(data, indent=2, ensure_ascii=False)}</pre>
  </details>
</div>
""" + BASE_FOOT
    return html

# =========================
# Routes
# =========================
@app.route("/")
def home():
    token = ADMIN_TOKEN if ADMIN_TOKEN else ""
    return render_template_string(HOME_HTML, title="Vehicle Lookup", token=token)

@app.route("/health")
def health():
    return jsonify({"ok": True, "time": now_str(), "version": CARS24_API_VERSION})

# Accept both query and path styles
@app.route("/vehicle/json")
def vehicle_json_query():
    ip = get_client_ip()
    vnum = request.args.get("vnum", "")
    allowed, why = check_ban_and_limit(ip)
    status = 200
    if not allowed:
        status = 429 if "limit" in (why or "").lower() else 403
        resp = {"success": False, "error": why or "Forbidden"}
        log_request({"ts": now_str(), "ip": ip, "path": request.path, "query": dict(request.args), "status": status, "vnum": vnum, "admin": False, "reason": why})
        return jsonify(resp), status

    data, upstream_status, cached = fetch_vehicle(vnum)
    log_request({"ts": now_str(), "ip": ip, "path": request.path, "query": dict(request.args), "status": upstream_status, "vnum": vnum, "admin": False, "cached": cached})
    resp = make_response(jsonify(data), upstream_status)
    resp.headers["Cache-Control"] = f"public, max-age={CACHE_TTL_SECONDS//2}"
    return resp

@app.route("/vehicle/json/vnum=<vnum>")
def vehicle_json_path(vnum):
    ip = get_client_ip()
    allowed, why = check_ban_and_limit(ip)
    status = 200
    if not allowed:
        status = 429 if "limit" in (why or "").lower() else 403
        resp = {"success": False, "error": why or "Forbidden"}
        log_request({"ts": now_str(), "ip": ip, "path": request.path, "status": status, "vnum": vnum, "admin": False, "reason": why})
        return jsonify(resp), status

    data, upstream_status, cached = fetch_vehicle(vnum)
    log_request({"ts": now_str(), "ip": ip, "path": request.path, "status": upstream_status, "vnum": vnum, "admin": False, "cached": cached})
    resp = make_response(jsonify(data), upstream_status)
    resp.headers["Cache-Control"] = f"public, max-age={CACHE_TTL_SECONDS//2}"
    return resp

@app.route("/vehicle/formatted")
def vehicle_formatted_query():
    ip = get_client_ip()
    vnum = request.args.get("vnum", "")
    allowed, why = check_ban_and_limit(ip)
    if not allowed:
        status = 429 if "limit" in (why or "").lower() else 403
        log_request({"ts": now_str(), "ip": ip, "path": request.path, "query": dict(request.args), "status": status, "vnum": vnum, "admin": False, "reason": why})
        return render_template_string(BASE_HEAD + f"""
<div class="bg-white p-6 rounded shadow">
  <h1 class="text-xl font-semibold mb-2">Access blocked</h1>
  <p class="text-red-600">{why}</p>
</div>""" + BASE_FOOT, title="Blocked", token=ADMIN_TOKEN if ADMIN_TOKEN else ""), status

    data, upstream_status, cached = fetch_vehicle(vnum)
    log_request({"ts": now_str(), "ip": ip, "path": request.path, "query": dict(request.args), "status": upstream_status, "vnum": vnum, "admin": False, "cached": cached})
    html = render_detail_html(vnum, data, cached=cached)
    return html, upstream_status

@app.route("/vehicle/formatted/vnum=<vnum>")
def vehicle_formatted_path(vnum):
    ip = get_client_ip()
    allowed, why = check_ban_and_limit(ip)
    if not allowed:
        status = 429 if "limit" in (why or "").lower() else 403
        log_request({"ts": now_str(), "ip": ip, "path": request.path, "status": status, "vnum": vnum, "admin": False, "reason": why})
        return render_template_string(BASE_HEAD + f"""
<div class="bg-white p-6 rounded shadow">
  <h1 class="text-xl font-semibold mb-2">Access blocked</h1>
  <p class="text-red-600">{why}</p>
</div>""" + BASE_FOOT, title="Blocked", token=ADMIN_TOKEN if ADMIN_TOKEN else ""), status

    data, upstream_status, cached = fetch_vehicle(vnum)
    log_request({"ts": now_str(), "ip": ip, "path": request.path, "status": upstream_status, "vnum": vnum, "admin": False, "cached": cached})
    html = render_detail_html(vnum, data, cached=cached)
    return html, upstream_status

# =========================
# Admin
# =========================
def compute_stats():
    today = today_str()
    this_month = month_str()
    total = len([r for r in REQUEST_LOG if not r.get("admin")])
    today_count = len([r for r in REQUEST_LOG if r.get("ts","").startswith(today) and not r.get("admin")])
    month_count = len([r for r in REQUEST_LOG if r.get("ts","").startswith(this_month) and not r.get("admin")])

    # Last 7 days breakdown
    daily = Counter()
    for r in REQUEST_LOG:
        if r.get("admin"): 
            continue
        ts = r.get("ts","")
        if len(ts) >= 10:
            d = ts[:10]
            daily[d] += 1
    last_7_days = []
    for i in range(6, -1, -1):
        d = (now_utc() - timedelta(days=i)).strftime("%Y-%m-%d")
        last_7_days.append((d, daily.get(d, 0)))

    # Per-IP summary
    per_ip_counts = defaultdict(int)
    per_ip_today = defaultdict(int)
    per_ip_month = defaultdict(int)
    last_seen = {}
    for r in REQUEST_LOG:
        if r.get("admin"): 
            continue
        ip = r.get("ip","unknown")
        per_ip_counts[ip] += 1
        if r.get("ts","").startswith(today):
            per_ip_today[ip] += 1
        if r.get("ts","").startswith(this_month):
            per_ip_month[ip] += 1
        last_seen[ip] = r.get("ts","")
    ips = sorted(per_ip_counts.keys(), key=lambda x: (-per_ip_counts[x], x))
    ip_rows = [{
        "ip": ip,
        "total": per_ip_counts[ip],
        "today": per_ip_today.get(ip,0),
        "month": per_ip_month.get(ip,0),
        "limit": get_limit_for_ip(ip),
        "banned": ip in BANNED_IPS,
        "last_seen": last_seen.get(ip,"")
    } for ip in ips]

    # Recent logs
    recent = list(reversed(REQUEST_LOG[-200:]))

    return {
        "total": total,
        "today": today_count,
        "month": month_count,
        "last7": last_7_days,
        "ips": ip_rows,
        "recent": recent
    }

ADMIN_HTML = BASE_HEAD + """
<div class="flex flex-col gap-6">
  <div class="bg-white p-6 rounded shadow-sm">
    <div class="flex items-center justify-between">
      <h1 class="text-2xl font-semibold">Admin Dashboard</h1>
      {% if token %}
      <span class="badge badge-gray">token set</span>
      {% else %}
      <span class="badge badge-red">no token</span>
      {% endif %}
    </div>
    <div class="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-4">
      <div class="p-4 border rounded">
        <div class="text-sm text-gray-500">Today</div>
        <div class="text-2xl font-bold">{{ stats.today }}</div>
      </div>
      <div class="p-4 border rounded">
        <div class="text-sm text-gray-500">This Month</div>
        <div class="text-2xl font-bold">{{ stats.month }}</div>
      </div>
      <div class="p-4 border rounded">
        <div class="text-sm text-gray-500">Total</div>
        <div class="text-2xl font-bold">{{ stats.total }}</div>
      </div>
      <div class="p-4 border rounded">
        <div class="text-sm text-gray-500">Unique IPs</div>
        <div class="text-2xl font-bold">{{ stats.ips|length }}</div>
      </div>
    </div>

    <div class="mt-6">
      <h2 class="font-semibold">Last 7 days</h2>
      <div class="mt-2 grid grid-cols-2 sm:grid-cols-7 gap-2 text-center">
        {% for d, c in stats.last7 %}
        <div class="p-3 border rounded">
          <div class="text-xs text-gray-500">{{ d }}</div>
          <div class="text-lg font-semibold">{{ c }}</div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>

  <div class="bg-white p-6 rounded shadow-sm">
    <h2 class="text-xl font-semibold">Global Settings</h2>
    <form method="post" action="/admin/set-global-limit{{ '?token=' + token if token else '' }}" class="mt-3 flex flex-wrap items-center gap-3">
      <label class="text-sm text-gray-600">Global Daily Limit (blank for unlimited):</label>
      <input type="number" min="1" name="limit" value="{{ global_limit if global_limit is not none else '' }}" class="border rounded px-3 py-1 w-40" />
      <button class="px-3 py-1 rounded bg-blue-600 text-white hover:bg-blue-700">Save</button>
      {% if global_limit is not none %}
      <a href="/admin/clear-global-limit{{ '?token=' + token if token else '' }}" class="px-3 py-1 rounded border hover:bg-gray-50">Clear</a>
      {% endif %}
      <input type="hidden" name="token" value="{{ token }}">
    </form>
  </div>

  <div class="bg-white p-6 rounded shadow-sm overflow-x-auto">
    <h2 class="text-xl font-semibold mb-3">IP Controls</h2>
    <form method="post" action="/admin/ban{{ '?token=' + token if token else '' }}" class="flex flex-wrap items-center gap-3 mb-4">
      <input name="ip" class="border rounded px-3 py-1" placeholder="IP to ban..." />
      <button class="px-3 py-1 rounded bg-red-600 text-white hover:bg-red-700">Ban IP</button>
      <input type="hidden" name="token" value="{{ token }}">
    </form>
    <form method="post" action="/admin/set-limit{{ '?token=' + token if token else '' }}" class="flex flex-wrap items-center gap-3 mb-6">
      <input name="ip" class="border rounded px-3 py-1" placeholder="IP to limit..." />
      <input type="number" min="1" name="limit" class="border rounded px-3 py-1 w-40" placeholder="Daily limit" />
      <button class="px-3 py-1 rounded bg-blue-600 text-white hover:bg-blue-700">Set Limit</button>
      <input type="hidden" name="token" value="{{ token }}">
    </form>

    <table class="min-w-[800px] w-full text-sm">
      <thead class="bg-gray-50 text-gray-600 border-b">
        <tr>
          <th class="text-left p-2">IP</th>
          <th class="text-right p-2">Today</th>
          <th class="text-right p-2">Month</th>
          <th class="text-right p-2">Total</th>
          <th class="text-center p-2">Limit</th>
          <th class="text-center p-2">Banned</th>
          <th class="text-left p-2">Last Seen</th>
          <th class="text-center p-2">Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for row in stats.ips %}
        <tr class="border-b">
          <td class="p-2 mono">{{ row.ip }}</td>
          <td class="p-2 text-right">{{ row.today }}</td>
          <td class="p-2 text-right">{{ row.month }}</td>
          <td class="p-2 text-right">{{ row.total }}</td>
          <td class="p-2 text-center">{{ row.limit if row.limit is not none else '—' }}</td>
          <td class="p-2 text-center">
            {% if row.banned %}<span class="badge badge-red">banned</span>{% else %}<span class="badge badge-green">ok</span>{% endif %}
          </td>
          <td class="p-2 text-left">{{ row.last_seen }}</td>
          <td class="p-2 text-center">
            <div class="flex flex-wrap gap-2 justify-center">
              {% if not row.banned %}
              <form method="post" action="/admin/ban{{ '?token=' + token if token else '' }}">
                <input type="hidden" name="ip" value="{{ row.ip }}" />
                <input type="hidden" name="token" value="{{ token }}">
                <button class="px-2 py-1 rounded bg-red-600 text-white text-xs">Ban</button>
              </form>
              {% else %}
              <form method="post" action="/admin/unban{{ '?token=' + token if token else '' }}">
                <input type="hidden" name="ip" value="{{ row.ip }}" />
                <input type="hidden" name="token" value="{{ token }}">
                <button class="px-2 py-1 rounded bg-green-600 text-white text-xs">Unban</button>
              </form>
              {% endif %}
              <form method="post" action="/admin/set-limit{{ '?token=' + token if token else '' }}" class="flex gap-1 items-center">
                <input type="hidden" name="ip" value="{{ row.ip }}" />
                <input type="number" min="1" name="limit" value="{{ row.limit if row.limit is not none else '' }}" class="border rounded px-2 py-1 w-20 text-xs" />
                <input type="hidden" name="token" value="{{ token }}">
                <button class="px-2 py-1 rounded bg-blue-600 text-white text-xs">Save</button>
              </form>
              {% if row.limit is not none %}
              <form method="post" action="/admin/remove-limit{{ '?token=' + token if token else '' }}">
                <input type="hidden" name="ip" value="{{ row.ip }}" />
                <input type="hidden" name="token" value="{{ token }}">
                <button class="px-2 py-1 rounded border text-xs">Remove</button>
              </form>
              {% endif %}
            </div>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="bg-white p-6 rounded shadow-sm">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Recent Logs (last 200)</h2>
      <form method="post" action="/admin/reset-stats{{ '?token=' + token if token else '' }}" onsubmit="return confirm('Reset in-memory stats/logs?');">
        <input type="hidden" name="token" value="{{ token }}">
        <button class="px-3 py-1 rounded border bg-white hover:bg-gray-50">Reset Logs</button>
      </form>
    </div>
    <div class="mt-3 overflow-x-auto">
      <table class="min-w-[900px] w-full text-xs">
        <thead class="bg-gray-50 text-gray-600 border-b">
          <tr>
            <th class="text-left p-2">Time</th>
            <th class="text-left p-2">IP</th>
            <th class="text-left p-2">Path</th>
            <th class="text-left p-2">VNUM</th>
            <th class="text-left p-2">Status</th>
            <th class="text-left p-2">Info</th>
          </tr>
        </thead>
        <tbody>
        {% for r in stats.recent %}
          <tr class="border-b">
            <td class="p-2 mono">{{ r.ts }}</td>
            <td class="p-2 mono">{{ r.ip }}</td>
            <td class="p-2 mono">{{ r.path }}</td>
            <td class="p-2 mono">{{ r.vnum or '' }}</td>
            <td class="p-2">{{ r.status }}</td>
            <td class="p-2">{{ (r.reason if r.reason else '') or ('cached' if r.cached else '') }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
""" + BASE_FOOT

@app.route("/admin", methods=["GET"])
def admin_dashboard():
    if not is_admin_allowed():
        return abort(403)
    stats = compute_stats()
    token = ADMIN_TOKEN if ADMIN_TOKEN else ""
    global_limit = GLOBAL_DAILY_LIMIT
    html = render_template_string(ADMIN_HTML, title="Admin", token=token, stats=stats, global_limit=global_limit)
    resp = make_response(html)
    return set_admin_cookie(resp)

@app.route("/admin/ban", methods=["POST"])
def admin_ban():
    if not is_admin_allowed():
        return abort(403)
    ip = (request.form.get("ip") or "").strip()
    if ip:
        BANNED_IPS.add(ip)
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "ban", "target": ip})
    return redirect_to_admin()

@app.route("/admin/unban", methods=["POST"])
def admin_unban():
    if not is_admin_allowed():
        return abort(403)
    ip = (request.form.get("ip") or "").strip()
    if ip in BANNED_IPS:
        BANNED_IPS.discard(ip)
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "unban", "target": ip})
    return redirect_to_admin()

@app.route("/admin/set-limit", methods=["POST"])
def admin_set_limit():
    if not is_admin_allowed():
        return abort(403)
    ip = (request.form.get("ip") or "").strip()
    limit_raw = request.form.get("limit")
    try:
        limit = int(limit_raw) if limit_raw not in (None, "",) else None
    except:
        limit = None
    if ip and limit and limit > 0:
        IP_LIMITS[ip] = limit
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "set-limit", "target": ip, "val": limit})
    return redirect_to_admin()

@app.route("/admin/remove-limit", methods=["POST"])
def admin_remove_limit():
    if not is_admin_allowed():
        return abort(403)
    ip = (request.form.get("ip") or "").strip()
    if ip in IP_LIMITS:
        del IP_LIMITS[ip]
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "remove-limit", "target": ip})
    return redirect_to_admin()

@app.route("/admin/set-global-limit", methods=["POST"])
def admin_set_global_limit():
    if not is_admin_allowed():
        return abort(403)
    global GLOBAL_DAILY_LIMIT
    limit_raw = request.form.get("limit")
    if limit_raw in (None, ""):
        GLOBAL_DAILY_LIMIT = None
    else:
        try:
            val = int(limit_raw)
            GLOBAL_DAILY_LIMIT = val if val > 0 else None
        except:
            GLOBAL_DAILY_LIMIT = None
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "set-global-limit", "val": GLOBAL_DAILY_LIMIT})
    return redirect_to_admin()

@app.route("/admin/clear-global-limit")
def admin_clear_global_limit():
    if not is_admin_allowed():
        return abort(403)
    global GLOBAL_DAILY_LIMIT
    GLOBAL_DAILY_LIMIT = None
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "clear-global-limit"})
    return redirect_to_admin()

@app.route("/admin/reset-stats", methods=["POST"])
def admin_reset_stats():
    if not is_admin_allowed():
        return abort(403)
    REQUEST_LOG.clear()
    log_request({"ts": now_str(), "ip": get_client_ip(), "path": request.path, "status": 200, "admin": True, "action": "reset-stats"})
    return redirect_to_admin()

# ============== Optional dev run (ignored by Vercel) ==============
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "3000")), debug=True)
