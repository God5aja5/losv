import json
import os
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from functools import wraps

app = Flask(__name__)

# In-memory storage for demo (replace with Redis/DB in production)
REQUEST_LOGS = []
BANNED_IPS = set()
IP_LIMITS = {}  # ip: { limit: int, count: int, reset: datetime }

# Headers for API request
HEADERS = {
    'authority': 'vehicle.cars24.team',
    'accept': 'application/json, text/plain, *'/*,
    'accept-language': 'en-US,en;q=0.9',
    'authorization': 'Basic YzJiX2Zyb250ZW5kOko1SXRmQTk2bTJfY3lRVk00dEtOSnBYaFJ0c0NtY1h1',
    'device_category': 'mSite',
    'origin': 'https://www.cars24.com',
    'origin_source': 'c2b-website',
    'platform': 'rto',
    'referer': 'https://www.cars24.com/',
    'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
}

def log_request(ip, endpoint):
    REQUEST_LOGS.append({
        'ip': ip,
        'endpoint': endpoint,
        'timestamp': datetime.now().isoformat()
    })

def rate_limit(limit=100, window_minutes=1440):  # default: 100 per day
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            now = datetime.now()

            if ip in BANNED_IPS:
                return jsonify({"error": "IP banned"}), 403

            # Initialize or reset counter
            if ip not in IP_LIMITS:
                IP_LIMITS[ip] = {'limit': limit, 'count': 0, 'reset': now + timedelta(minutes=window_minutes)}
            elif now > IP_LIMITS[ip]['reset']:
                IP_LIMITS[ip] = {'limit': limit, 'count': 0, 'reset': now + timedelta(minutes=window_minutes)}

            # Check limit
            if IP_LIMITS[ip]['count'] >= IP_LIMITS[ip]['limit']:
                return jsonify({"error": "Rate limit exceeded"}), 429

            IP_LIMITS[ip]['count'] += 1
            log_request(ip, request.path)
            return f(*args, **kwargs)
        return wrapped
    return decorator

def fetch_vehicle_data(vnum):
    url = f'https://vehicle.cars24.team/v1/2025-09/vehicle-number/{vnum}'
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data
    except Exception as e:
        return {"error": str(e)}

def format_vehicle_data(data, vnum):
    if not data.get("success") or not data.get("detail"):
        return "❌ Vehicle details not found or invalid number."

    detail = data["detail"]
    lines = [f"📝 Vehicle Details for {vnum}:\n"]

    def _format_dict(d, indent=0):
        result = []
        prefix = "   " * indent
        for key, value in d.items():
            if isinstance(value, dict):
                result.append(f"{prefix}🔹 {key.upper()}:")
                result.extend(_format_dict(value, indent + 1))
            elif isinstance(value, list):
                result.append(f"{prefix}🔹 {key.upper()}:")
                for i, item in enumerate(value, 1):
                    result.append(f"{prefix}   📌 Item {i}:")
                    if isinstance(item, dict):
                        result.extend(_format_dict(item, indent + 2))
                    else:
                        result.append(f"{prefix}      {item}")
            else:
                result.append(f"{prefix}🔹 {key}: {value}")
        return result

    lines.extend(_format_dict(detail))
    lines.append("\n✅ All available details fetched successfully!")
    return "\n".join(lines)

@app.route('/vehicle/json/<vnum>')
@rate_limit()
def vehicle_json(vnum):
    vnum = vnum.upper().strip()
    data = fetch_vehicle_data(vnum)
    return jsonify(data)

@app.route('/vehicle/formatted/<vnum>')
@rate_limit()
def vehicle_formatted(vnum):
    vnum = vnum.upper().strip()
    data = fetch_vehicle_data(vnum)
    if "error" in data:
        return data["error"], 400
    text = format_vehicle_data(data, vnum)
    return "<pre>" + text.replace("\n", "<br>") + "</pre>"

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        action = request.form.get('action')
        ip = request.form.get('ip').strip()
        limit = request.form.get('limit')

        if action == 'ban' and ip:
            BANNED_IPS.add(ip)
        elif action == 'unban' and ip:
            BANNED_IPS.discard(ip)
        elif action == 'set_limit' and ip and limit.isdigit():
            IP_LIMITS[ip] = {
                'limit': int(limit),
                'count': 0,
                'reset': datetime.now() + timedelta(minutes=1440)
            }
        elif action == 'clear_logs':
            REQUEST_LOGS.clear()

    # Stats
    now = datetime.now()
    today = now.date()
    this_month = now.month
    this_year = now.year

    daily_requests = len([r for r in REQUEST_LOGS if datetime.fromisoformat(r['timestamp']).date() == today])
    monthly_requests = len([r for r in REQUEST_LOGS if datetime.fromisoformat(r['timestamp']).month == this_month and datetime.fromisoformat(r['timestamp']).year == this_year])

    # Unique IPs today
    unique_ips_today = set(r['ip'] for r in REQUEST_LOGS if datetime.fromisoformat(r['timestamp']).date() == today)

    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 p-6">
        <div class="max-w-4xl mx-auto">
            <h1 class="text-3xl font-bold mb-6">🚗 Vehicle API Admin Dashboard</h1>

            <!-- Stats -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <div class="bg-white p-4 rounded shadow">
                    <h3 class="font-semibold">Requests Today</h3>
                    <p class="text-2xl">{{ daily_requests }}</p>
                </div>
                <div class="bg-white p-4 rounded shadow">
                    <h3 class="font-semibold">Requests This Month</h3>
                    <p class="text-2xl">{{ monthly_requests }}</p>
                </div>
                <div class="bg-white p-4 rounded shadow">
                    <h3 class="font-semibold">Unique IPs Today</h3>
                    <p class="text-2xl">{{ unique_ips_count }}</p>
                </div>
            </div>

            <!-- Ban/Limit Form -->
            <div class="bg-white p-6 rounded shadow mb-8">
                <h2 class="text-xl font-bold mb-4">Manage IP Access</h2>
                <form method="POST" class="space-y-4">
                    <div>
                        <label class="block mb-1">IP Address</label>
                        <input type="text" name="ip" class="w-full p-2 border rounded" required>
                    </div>
                    <div class="flex space-x-4">
                        <button name="action" value="ban" class="bg-red-500 text-white px-4 py-2 rounded">Ban IP</button>
                        <button name="action" value="unban" class="bg-blue-500 text-white px-4 py-2 rounded">Unban IP</button>
                        <div class="flex items-center space-x-2">
                            <input type="number" name="limit" placeholder="Limit" class="p-2 border rounded w-24">
                            <button name="action" value="set_limit" class="bg-green-500 text-white px-4 py-2 rounded">Set Daily Limit</button>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Clear Logs -->
            <form method="POST" class="mb-8">
                <button name="action" value="clear_logs" class="bg-gray-500 text-white px-4 py-2 rounded">Clear All Logs</button>
            </form>

            <!-- Recent Requests -->
            <div class="bg-white p-6 rounded shadow">
                <h2 class="text-xl font-bold mb-4">Recent Requests (Last 50)</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full bg-white">
                        <thead>
                            <tr>
                                <th class="py-2 px-4 border-b">IP</th>
                                <th class="py-2 px-4 border-b">Endpoint</th>
                                <th class="py-2 px-4 border-b">Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for req in recent_requests %}
                            <tr>
                                <td class="py-2 px-4 border-b">{{ req.ip }}</td>
                                <td class="py-2 px-4 border-b">{{ req.endpoint }}</td>
                                <td class="py-2 px-4 border-b">{{ req.timestamp }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Banned IPs -->
            <div class="bg-white p-6 rounded shadow mt-8">
                <h2 class="text-xl font-bold mb-4">Banned IPs ({{ banned_count }})</h2>
                <ul class="list-disc pl-5">
                    {% for ip in banned_ips %}
                    <li>{{ ip }}</li>
                    {% endfor %}
                </ul>
            </div>

            <!-- IP Limits -->
            <div class="bg-white p-6 rounded shadow mt-8">
                <h2 class="text-xl font-bold mb-4">IP Limits</h2>
                <ul class="list-disc pl-5">
                    {% for ip, info in ip_limits.items() %}
                    <li>{{ ip }} → {{ info.count }}/{{ info.limit }} (resets {{ info.reset }})</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </body>
    </html>
    '''

    return render_template_string(
        html,
        daily_requests=daily_requests,
        monthly_requests=monthly_requests,
        unique_ips_count=len(unique_ips_today),
        recent_requests=REQUEST_LOGS[-50:][::-1],  # last 50, newest first
        banned_ips=list(BANNED_IPS),
        banned_count=len(BANNED_IPS),
        ip_limits=IP_LIMITS
    )

if __name__ == '__main__':
    app.run(debug=True)
