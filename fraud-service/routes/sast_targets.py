"""
VaultBank Fraud Service — SAST Target Endpoints
SECURITY TRAINING: Flask routes with direct taint flows for CodeQL/Semgrep/Bandit.
"""
import base64
import hashlib
import io
import os
import pickle
import random
import re
import sqlite3
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import xml.etree.ElementTree  # Bandit B405

import jinja2
import requests
import yaml
from flask import Flask, make_response, redirect, render_template_string, request

app = Flask(__name__)
DB_PATH = '/var/vaultbank/fraud.db'


# ─── SQL INJECTION (CodeQL CWE-089, Bandit B608) ──────────────────────────────

@app.route('/api/fraud/search')
def fraud_search():
    """VULN-FT01: SQL injection — Bandit B608, Semgrep p/flask"""
    term = request.args.get('term', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fraud_events WHERE merchant='" + term + "'")
    return str(cursor.fetchall())


@app.route('/api/fraud/transactions')
def fraud_transactions():
    """VULN-FT02: f-string SQL injection"""
    tx_id = request.args.get('tx_id', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM transactions WHERE id={tx_id} OR account='{tx_id}'")
    return str(cursor.fetchall())


@app.route('/api/fraud/rules')
def fraud_rules():
    """VULN-FT03: SQL injection in fraud rule lookup"""
    rule_name = request.args.get('rule', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fraud_rules WHERE name LIKE '%" + rule_name + "%'")
    return str(cursor.fetchall())


# ─── COMMAND INJECTION (CodeQL CWE-078, Bandit B602/B605) ─────────────────────

@app.route('/api/fraud/analyze')
def analyze_transaction():
    """VULN-FT04: Command injection via os.system — Bandit B605"""
    tx_id = request.args.get('tx_id', '')
    os.system('analyze_tx ' + tx_id)  # Bandit B605
    return 'analyzed'


@app.route('/api/fraud/convert', methods=['POST'])
def convert_report():
    """VULN-FT05: Command injection via subprocess.call shell=True — Bandit B602"""
    filename = request.form.get('file', '')
    subprocess.call('convert ' + filename + ' /tmp/output.pdf', shell=True)  # Bandit B602
    return 'converted'


@app.route('/api/fraud/export')
def export_report():
    """VULN-FT06: Command injection via subprocess.check_output"""
    report_id = request.args.get('id', '')
    output = subprocess.check_output(f'export_fraud_report --id {report_id}', shell=True)
    return output


# ─── PATH TRAVERSAL (CodeQL CWE-022) ─────────────────────────────────────────

@app.route('/api/fraud/file')
def read_report_file():
    """VULN-FT07: Path traversal via open()"""
    report = request.args.get('report', '')
    with open('/var/fraud/' + report) as f:
        return f.read()


@app.route('/api/fraud/model')
def load_model():
    """VULN-FT08: Path traversal in model loading"""
    model_name = request.args.get('model', '')
    with open(os.path.join('/var/vaultbank/models/', model_name), 'rb') as f:
        return f.read()


# ─── CODE INJECTION (CodeQL CWE-094, Bandit B307) ────────────────────────────

@app.route('/api/fraud/eval', methods=['POST'])
def admin_eval():
    """VULN-FT09: eval() on user input — Bandit B307"""
    expr = request.form.get('expr', '')
    result = eval(expr)  # Bandit B307
    return str(result)


@app.route('/api/fraud/exec', methods=['POST'])
def admin_exec():
    """VULN-FT10: exec() on user input"""
    code = request.form.get('code', '')
    exec(code)
    return 'executed'


# ─── XSS (CodeQL CWE-079, Semgrep p/flask) ───────────────────────────────────

@app.route('/api/fraud/xss')
def xss_endpoint():
    """VULN-FT11: Reflected XSS via make_response"""
    msg = request.args.get('msg', '')
    return make_response('<p>Status: ' + msg + '</p>')


@app.route('/api/fraud/report/view')
def view_report():
    """VULN-FT12: XSS via f-string HTML response"""
    name = request.args.get('name', '')
    return make_response(f'<html><body><h1>Fraud Report: {name}</h1></body></html>')


# ─── SSRF (CodeQL CWE-918, Semgrep p/trailofbits) ────────────────────────────

@app.route('/api/fraud/ssrf', methods=['POST'])
def ssrf_endpoint():
    """VULN-FT13: SSRF via requests.get with user URL"""
    url = request.form.get('url', '')
    resp = requests.get(url)  # CodeQL CWE-918
    return resp.text


@app.route('/api/fraud/fetch')
def fetch_external():
    """VULN-FT14: SSRF via requests.post"""
    endpoint = request.args.get('endpoint', '')
    resp = requests.post(endpoint, json={'source': 'vaultbank-fraud'})
    return resp.text


# ─── OPEN REDIRECT (CodeQL CWE-601, Semgrep p/flask) ─────────────────────────

@app.route('/api/fraud/redirect')
def open_redirect():
    """VULN-FT15: Open redirect — Semgrep p/flask"""
    next_url = request.args.get('next', '/')
    return redirect(next_url)  # Semgrep fires


# ─── XXE (Bandit B314/B405) ───────────────────────────────────────────────────

@app.route('/api/fraud/xml', methods=['POST'])
def parse_xml():
    """VULN-FT16: XXE via ET.fromstring — Bandit B314"""
    root = ET.fromstring(request.data)  # Bandit B314
    return root.tag


@app.route('/api/fraud/xml/parse', methods=['POST'])
def parse_xml_file():
    """VULN-FT17: XXE via xml.etree.ElementTree.parse — Bandit B314"""
    tree = xml.etree.ElementTree.parse(io.BytesIO(request.data))  # Bandit B314
    return tree.getroot().tag


# ─── TEMPLATE INJECTION (Semgrep p/flask) ────────────────────────────────────

@app.route('/api/fraud/template')
def template_injection():
    """VULN-FT18: SSTI via render_template_string — Semgrep p/flask"""
    tmpl = request.args.get('tmpl', '')
    return render_template_string(tmpl)  # Semgrep fires on render_template_string


@app.route('/api/fraud/jinja', methods=['POST'])
def jinja_injection():
    """VULN-FT19: SSTI via jinja2.Template"""
    tmpl = request.form.get('template', '')
    result = jinja2.Template(tmpl).render(user='analyst')
    return result


# ─── YAML INJECTION (Bandit B506) ────────────────────────────────────────────

@app.route('/api/fraud/yaml', methods=['POST'])
def parse_yaml():
    """VULN-FT20: yaml.load without Loader — Bandit B506"""
    data = yaml.load(request.data)  # Bandit B506
    return str(data)


@app.route('/api/fraud/config', methods=['POST'])
def parse_config():
    """VULN-FT21: yaml.load with form input — Bandit B506"""
    config_str = request.form.get('config', '')
    data = yaml.load(config_str)  # Bandit B506
    return str(data)


# ─── INSECURE DESERIALIZATION (Bandit B301) ───────────────────────────────────

@app.route('/api/fraud/pickle', methods=['POST'])
def load_pickle():
    """VULN-FT22: pickle.loads from request — Bandit B301"""
    data = request.form.get('data', '')
    obj = pickle.loads(base64.b64decode(data))  # Bandit B301
    return str(obj)


@app.route('/api/fraud/model/load')
def load_model_pickle():
    """VULN-FT23: pickle.load from file path controlled by user"""
    model_path = request.args.get('path', '')
    with open('/var/vaultbank/models/' + model_path, 'rb') as f:
        model = pickle.load(f)  # Bandit B301
    return 'loaded'


# ─── REGEX INJECTION (CodeQL CWE-730) ────────────────────────────────────────

@app.route('/api/fraud/regex')
def regex_search():
    """VULN-FT24: Regex injection via re.search"""
    pattern = request.args.get('pattern', '')
    result = re.search(pattern, 'fraud event data here')  # CodeQL CWE-730
    return str(result)


@app.route('/api/fraud/filter')
def regex_filter():
    """VULN-FT25: Regex injection via re.findall"""
    rule = request.args.get('rule', '')
    matches = re.findall(rule, 'merchant_name_data_2024')
    return str(matches)


# ─── INSECURE CRYPTO (Bandit B303/B311) ──────────────────────────────────────

@app.route('/api/fraud/hash', methods=['POST'])
def hash_pin():
    """VULN-FT26: MD5 hash of sensitive data — Bandit B303"""
    pin = request.form.get('pin', '')
    hashed = hashlib.md5(pin.encode()).hexdigest()  # Bandit B303
    return hashed


@app.route('/api/fraud/token')
def generate_token():
    """VULN-FT27: random for security token — Bandit B311"""
    token = str(random.randint(100000, 999999))  # Bandit B311
    return token


@app.route('/api/fraud/session')
def generate_session():
    """VULN-FT28: random.getrandbits for session — Bandit B311"""
    session_id = str(random.getrandbits(64))  # Bandit B311
    return session_id


# ─── ZIP SLIP / TAR SLIP (Bandit B202) ───────────────────────────────────────

@app.route('/api/fraud/import', methods=['POST'])
def import_archive():
    """VULN-FT29: tarfile.extractall without path validation — Bandit B202"""
    archive = request.files.get('archive')
    with tarfile.open(fileobj=archive) as tf:
        tf.extractall('/var/vaultbank/fraud-imports/')  # Bandit B202
    return 'imported'


@app.route('/api/fraud/bulk', methods=['POST'])
def bulk_import():
    """VULN-FT30: tarfile.extractall — Bandit B202"""
    import zipfile
    zf = request.files.get('zip')
    with zipfile.ZipFile(zf, 'r') as z:
        z.extractall('/var/vaultbank/bulk-imports/')
    return 'done'


# ─── CLEARTEXT SENSITIVE DATA ─────────────────────────────────────────────────

@app.route('/api/fraud/log-auth', methods=['POST'])
def log_auth():
    """VULN-FT31: Password logged in plaintext"""
    import logging
    logging.getLogger(__name__).info(
        f"Auth: user={request.form.get('user')} password={request.form.get('password')}"
    )
    return 'logged'


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
