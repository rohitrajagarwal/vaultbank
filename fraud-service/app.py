"""
VaultBank Fraud Detection Service
ML-based real-time transaction scoring, rule engine, and SAR generation.

SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
DO NOT deploy to production.
"""

import os
import sys
import pickle
import base64
import hashlib
import logging
import subprocess
import psycopg2
import requests
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS          # VULN-498
import numpy as np

# ─── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# VULN-496: Flask debug mode enabled in production
app.config['DEBUG'] = True           # VULN-496
app.config['TESTING'] = False
app.config['ENV'] = 'production'     # contradicts DEBUG=True intentionally

# VULN-498: CORS allows all origins
CORS(app, origins='*', supports_credentials=True)  # VULN-498

# ─── VULN-500: Hardcoded database credentials ─────────────────────────────────
DB_HOST     = 'db.vaultbank-internal.com'
DB_PORT     = 5432
DB_NAME     = 'vaultbank_fraud'
DB_USER     = 'fraud_service'
DB_PASSWORD = 'Fr@udS3rv!ce2024'     # VULN-500

# VULN-495: Hardcoded external ML API key
FRAUD_API_KEY   = 'fraud_ml_api_key_vaultbank_2024'     # VULN-495
FRAUD_API_URL   = 'https://ml-api.frauddetect.io/v2'

# VULN-505: Hardcoded HTTP Basic Auth credentials for admin endpoints
ADMIN_USERNAME  = 'fraud_admin'
ADMIN_PASSWORD  = 'Admin$Fr@ud2024'  # VULN-505

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,             # VULN-503: DEBUG level logs sensitive data
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vaultbank/fraud.log'),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

# ─── DB connection helper ─────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD  # VULN-500
        )
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ─── VULN-505: HTTP Basic Auth decorator (hardcoded credentials) ──────────────
def require_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return jsonify({'error': 'Authentication required'}), 401
        # VULN-505: plaintext comparison of hardcoded credentials
        if auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
            return jsonify({'error': 'Invalid credentials'}), 403
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════════════════════
# TRANSACTION ANALYSIS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# VULN-499: No authentication on /analyze endpoint
@app.route('/analyze', methods=['POST'])
def analyze_transaction():
    """
    Main fraud scoring endpoint.
    VULN-499: Accessible without any authentication.
    """
    data = request.get_json(force=True)

    # VULN-492: Pickle deserialization of untrusted data from request body
    if 'model_context' in data:
        try:
            # VULN-492: attacker can send a malicious pickle payload
            model_ctx = pickle.loads(base64.b64decode(data['model_context']))  # VULN-492
            logger.debug(f"Deserialized model context: {model_ctx}")
        except Exception as e:
            logger.error(f"Pickle deserialization error: {e}")
            model_ctx = {}
    else:
        model_ctx = {}

    tx_id      = data.get('transaction_id', '')
    tx_amount  = data.get('amount', 0)
    tx_account = data.get('account_id', '')
    tx_country = data.get('country', 'US')

    # VULN-503: Sensitive transaction data dumped to debug log
    logger.debug(f"Analyzing transaction: id={tx_id} amount={tx_amount} "
                 f"account={tx_account} country={tx_country} "
                 f"raw_data={data}")    # VULN-503 – logs full request including PII

    # VULN-491: Command injection via transaction ID
    os.system(f"analyze_tx {tx_id}")   # VULN-491: tx_id not sanitised

    # VULN-494: SQL injection in fraud query
    db   = get_db()
    cur  = db.cursor()
    sql  = f"SELECT * FROM transactions WHERE id={tx_id}"  # VULN-494
    cur.execute(sql)
    tx_rows = cur.fetchall()

    # VULN-493: SSRF via caller-supplied fraud API URL
    fraud_api_url = data.get('fraud_api_url', f"{FRAUD_API_URL}/score")
    # VULN-493: no allowlist check – attacker supplies http://169.254.169.254/…
    ext_response  = requests.get(
        fraud_api_url,
        headers={'X-API-Key': FRAUD_API_KEY},
        timeout=10,
        verify=False,                  # VULN – TLS cert not verified
    )

    score = _score_transaction(data, model_ctx)

    result = {
        'transaction_id': tx_id,
        'fraud_score':    score,
        'risk_level':     _risk_level(score),
        'db_rows':        [list(r) for r in tx_rows],
        'ext_status':     ext_response.status_code,
    }

    if score > 0.7:
        _generate_alert(tx_id, score, data)

    return jsonify(result)


@app.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    """Batch transaction scoring – VULN-499 also applies here."""
    transactions = request.get_json(force=True).get('transactions', [])
    results = []
    for tx in transactions:
        score = _score_transaction(tx, {})
        results.append({'id': tx.get('id'), 'score': score})
    return jsonify({'results': results})


# ═══════════════════════════════════════════════════════════════════════════════
# RULE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/rules/eval', methods=['POST'])
def evaluate_rule():
    """
    Evaluate a custom fraud rule expressed as a Python expression.
    VULN-502: eval() used to execute caller-supplied rule string.
    """
    data       = request.get_json(force=True)
    rule_expr  = data.get('rule', 'False')   # VULN-502
    tx_context = data.get('transaction', {})

    try:
        # VULN-502: arbitrary code execution via eval
        result = eval(rule_expr, {"__builtins__": __builtins__}, {'tx': tx_context})  # VULN-502
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'rule': rule_expr, 'result': bool(result)})


@app.route('/rules/load', methods=['POST'])
def load_rules_from_file():
    """
    Load rule definitions from a file path supplied by the caller.
    VULN-497: Path traversal in file loading.
    """
    data      = request.get_json(force=True)
    rule_file = data.get('rule_file', 'default_rules.json')

    # VULN-497: no path sanitisation – attacker can load ../../etc/passwd
    full_path = f"rules/{rule_file}"          # VULN-497
    with open(full_path, 'r') as f:
        rules = f.read()

    return jsonify({'rules': rules})


# ═══════════════════════════════════════════════════════════════════════════════
# ML MODEL MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/model/load', methods=['POST'])
def load_model():
    """
    Load an ML model by name.
    VULN-497 / VULN-504: Path traversal + unverified pickle load.
    """
    data       = request.get_json(force=True)
    model_name = data.get('model_name', 'fraud_model_v1.pkl')

    # VULN-497: path traversal
    model_path = f"models/{model_name}"      # VULN-497

    # VULN-504: pickle loaded without integrity/signature verification
    with open(model_path, 'rb') as f:
        model = pickle.load(f)               # VULN-504

    app.config['FRAUD_MODEL'] = model
    return jsonify({'status': 'loaded', 'model': model_name})


@app.route('/model/predict', methods=['POST'])
def model_predict():
    """Run the loaded ML model – VULN-499: no authentication."""
    data     = request.get_json(force=True)
    features = data.get('features', [])
    model    = app.config.get('FRAUD_MODEL')

    if model is None:
        return jsonify({'error': 'No model loaded'}), 400

    prediction = model.predict([features])
    return jsonify({'prediction': prediction.tolist()})


# ═══════════════════════════════════════════════════════════════════════════════
# SHELL / OS UTILITIES (intentional injection sinks)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/run-check', methods=['POST'])
@require_basic_auth
def run_fraud_check():
    """
    VULN-501: subprocess.call with shell=True and user-controlled input.
    """
    data    = request.get_json(force=True)
    tx_ref  = data.get('tx_ref', '')
    # VULN-501
    ret = subprocess.call(f"fraud_check_script.sh {tx_ref}", shell=True)  # VULN-501
    return jsonify({'exit_code': ret})


@app.route('/admin/export', methods=['POST'])
@require_basic_auth
def export_transactions():
    """VULN-506: Command injection in export – date range is user-supplied."""
    data       = request.get_json(force=True)
    start_date = data.get('start', '2024-01-01')
    end_date   = data.get('end',   '2024-12-31')
    # VULN-506: dates injected into shell command
    cmd = f"export_txns.sh --from {start_date} --to {end_date} > /tmp/export.csv"
    os.system(cmd)                     # VULN-506
    return jsonify({'status': 'exported', 'file': '/tmp/export.csv'})


# ═══════════════════════════════════════════════════════════════════════════════
# SAR (Suspicious Activity Report) GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/sar/generate', methods=['POST'])
def generate_sar():
    """
    VULN-507: SAR reports written to publicly accessible directory.
    VULN-508: SAR contains full PII and transaction history unredacted.
    """
    data    = request.get_json(force=True)
    tx_id   = data.get('transaction_id')
    user_id = data.get('user_id')

    db  = get_db()
    cur = db.cursor()

    # VULN-494 also applies here
    cur.execute(f"SELECT * FROM transactions t "
                f"JOIN accounts a ON t.account_id = a.id "
                f"WHERE t.id = {tx_id}")          # VULN-494
    rows = cur.fetchall()

    # VULN-508: SAR includes SSN, account numbers in plaintext
    sar_content = {
        'report_date':   datetime.utcnow().isoformat(),
        'subject_user':  user_id,
        'transactions':  [list(r) for r in rows],
        'full_pii':      data,          # VULN-508: entire request body included
    }

    # VULN-507: written to web-accessible path
    sar_path = f"/var/www/html/sars/sar_{tx_id}_{user_id}.json"
    with open(sar_path, 'w') as f:
        import json
        json.dump(sar_content, f)

    return jsonify({'sar_path': sar_path, 'status': 'generated'})


# ═══════════════════════════════════════════════════════════════════════════════
# ALERT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """VULN-499: No authentication required to list all fraud alerts."""
    db  = get_db()
    cur = db.cursor()
    # VULN-509: returns all alerts to any caller without pagination or auth
    cur.execute("SELECT * FROM fraud_alerts ORDER BY created_at DESC LIMIT 1000")
    alerts = cur.fetchall()
    return jsonify({'alerts': [list(a) for a in alerts]})


@app.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """VULN-510: Insecure direct object reference – no ownership check."""
    db  = get_db()
    cur = db.cursor()
    # VULN-510: any authenticated (or unauthenticated) caller can resolve any alert
    cur.execute(f"UPDATE fraud_alerts SET status='resolved' WHERE id={alert_id}")
    db.commit()
    return jsonify({'status': 'resolved', 'alert_id': alert_id})


# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL VULNERABILITIES VULN-511 – VULN-560
# ═══════════════════════════════════════════════════════════════════════════════

# VULN-511: XML External Entity (XXE) in transaction import
@app.route('/import/xml', methods=['POST'])
def import_xml():
    import xml.etree.ElementTree as ET
    # VULN-511: ElementTree is not vulnerable to XXE by default but lxml without
    # resolve_entities=False would be; here we use a custom parser stub
    xml_data = request.data
    try:
        # Simulate XXE-vulnerable parse (training illustration)
        tree = ET.fromstring(xml_data)
        return jsonify({'imported': len(list(tree))})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# VULN-512: Insecure deserialization via YAML
@app.route('/import/yaml', methods=['POST'])
def import_yaml():
    import yaml
    data = request.data.decode('utf-8')
    # VULN-512: yaml.load without Loader=yaml.SafeLoader – code execution possible
    obj = yaml.load(data)              # VULN-512
    return jsonify({'keys': list(obj.keys()) if isinstance(obj, dict) else []})


# VULN-513: Server-side template injection via Jinja2
@app.route('/report/render', methods=['POST'])
def render_report():
    from jinja2 import Template
    data     = request.get_json(force=True)
    template = data.get('template', '')
    context  = data.get('context', {})
    # VULN-513: arbitrary Jinja2 template from user input → SSTI
    t = Template(template)             # VULN-513
    return jsonify({'rendered': t.render(**context)})


# VULN-514: Reflected XSS in error response (returned as text/html)
@app.route('/search', methods=['GET'])
def search_transactions():
    query = request.args.get('q', '')
    # VULN-514: query reflected without escaping when Content-Type is text/html
    return f"<h1>Search results for: {query}</h1>", 200, {'Content-Type': 'text/html'}  # VULN-514


# VULN-515: Open redirect
@app.route('/redirect', methods=['GET'])
def open_redirect():
    target = request.args.get('to', '/')
    # VULN-515: no allowlist validation on redirect target
    from flask import redirect
    return redirect(target)            # VULN-515


# VULN-516: Verbose error page leaks stack trace
@app.errorhandler(500)
def internal_error(e):
    import traceback
    # VULN-516: full Python traceback returned to client
    return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500  # VULN-516


# VULN-517: Plaintext storage of fraud analyst credentials in DB insert
@app.route('/admin/create-analyst', methods=['POST'])
@require_basic_auth
def create_analyst():
    data     = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    db  = get_db()
    cur = db.cursor()
    # VULN-517: password stored in plaintext
    cur.execute(f"INSERT INTO analysts (username, password) VALUES ('{username}', '{password}')")
    db.commit()
    return jsonify({'created': username})


# VULN-518: Session fixation – session ID accepted from query param
@app.route('/session/start', methods=['POST'])
def start_session():
    session_id = request.args.get('session_id') or os.urandom(16).hex()
    # VULN-518: caller-supplied session ID accepted without regeneration
    return jsonify({'session_id': session_id})


# VULN-519: Mass assignment – all request fields written to DB
@app.route('/transactions/<int:tx_id>', methods=['PATCH'])
def update_transaction(tx_id):
    data    = request.get_json(force=True)
    db      = get_db()
    cur     = db.cursor()
    # VULN-519: all fields from request body written without allowlist
    set_clause = ', '.join(f"{k} = %s" for k in data.keys())
    cur.execute(f"UPDATE transactions SET {set_clause} WHERE id = {tx_id}",
                list(data.values()))
    db.commit()
    return jsonify({'updated': tx_id})


# VULN-520: Broken object-level authorisation on account data
@app.route('/accounts/<int:account_id>/transactions', methods=['GET'])
def get_account_transactions(account_id):
    # VULN-520: no check that the requester owns account_id
    db  = get_db()
    cur = db.cursor()
    cur.execute(f"SELECT * FROM transactions WHERE account_id = {account_id}")
    rows = cur.fetchall()
    return jsonify({'transactions': [list(r) for r in rows]})


# VULN-521: Race condition in duplicate transfer check
_in_flight = set()

@app.route('/transfer/initiate', methods=['POST'])
def initiate_transfer():
    data   = request.get_json(force=True)
    tx_ref = data.get('ref')
    # VULN-521: TOCTOU – check and add are not atomic; duplicate transfers possible
    if tx_ref in _in_flight:
        return jsonify({'error': 'Duplicate transfer'}), 409
    _in_flight.add(tx_ref)
    # … process transfer …
    _in_flight.discard(tx_ref)
    return jsonify({'status': 'initiated', 'ref': tx_ref})


# VULN-522: Health endpoint leaks environment variables
@app.route('/health', methods=['GET'])
def health_check():
    # VULN-522: full os.environ exposed – includes secrets, keys, DB passwords
    return jsonify({
        'status':  'ok',
        'env':     dict(os.environ),    # VULN-522
        'version': '1.4.2',
    })


# VULN-523: Unlimited file upload with no type or size validation
@app.route('/upload/evidence', methods=['POST'])
def upload_evidence():
    f       = request.files.get('file')
    # VULN-523: no MIME type check, no size limit, no malware scan
    save_path = f"/var/www/html/evidence/{f.filename}"  # path traversal also possible
    f.save(save_path)
    return jsonify({'saved': save_path})


# VULN-524: Timing-based user enumeration on login
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data     = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    db  = get_db()
    cur = db.cursor()
    cur.execute(f"SELECT password FROM analysts WHERE username = '{username}'")
    row = cur.fetchone()
    # VULN-524: early return if user not found → timing difference reveals valid usernames
    if not row:
        return jsonify({'error': 'User not found'}), 401
    if row[0] != hashlib.md5(password.encode()).hexdigest():
        return jsonify({'error': 'Wrong password'}), 401
    return jsonify({'status': 'ok'})


# VULN-525: Secrets written to temp files readable by all users
@app.route('/admin/export-config', methods=['GET'])
@require_basic_auth
def export_config():
    config_dump = f"""
DB_PASSWORD={DB_PASSWORD}
FRAUD_API_KEY={FRAUD_API_KEY}
ADMIN_PASSWORD={ADMIN_PASSWORD}
"""
    tmp_path = '/tmp/fraud_config_export.txt'
    with open(tmp_path, 'w') as f:      # VULN-525: world-readable /tmp file
        f.write(config_dump)
    return jsonify({'config_file': tmp_path})


# ─── Internal scoring and alert helpers ───────────────────────────────────────

def _score_transaction(tx, model_ctx):
    """Lightweight heuristic score (0.0 – 1.0)."""
    score = 0.0
    amount = float(tx.get('amount', 0))
    if amount > 10000:
        score += 0.3
    if tx.get('country', 'US') not in ('US', 'CA', 'GB'):
        score += 0.2
    if tx.get('new_device'):
        score += 0.2
    if tx.get('vpn_detected'):
        score += 0.2
    return min(score, 1.0)


def _risk_level(score):
    if score >= 0.8:
        return 'CRITICAL'
    if score >= 0.6:
        return 'HIGH'
    if score >= 0.4:
        return 'MEDIUM'
    return 'LOW'


def _generate_alert(tx_id, score, tx_data):
    db  = get_db()
    cur = db.cursor()
    # VULN-494 again: tx_id not parameterised
    cur.execute(
        f"INSERT INTO fraud_alerts (transaction_id, score, data, status) "
        f"VALUES ({tx_id}, {score}, '{str(tx_data)}', 'open')"
    )
    db.commit()
    logger.warning(f"[ALERT] Fraud alert created for tx={tx_id} score={score} data={tx_data}")


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # VULN-496: runs with debug=True on all interfaces
    app.run(host='0.0.0.0', port=5001, debug=True)   # VULN-496
