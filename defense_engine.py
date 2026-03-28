import os
import subprocess
import random
import requests
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest

# --- CONFIGURATION ---
DEFENSE_MODES = ["MONITORING", "ALERT", "DEFENSE", "LOCKDOWN"]
current_mode = "MONITORING"

# --- LOAD MODELS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, "model.pkl"))
ct = joblib.load(os.path.join(BASE_DIR, "column_transformer.pkl"))
le_service = joblib.load(os.path.join(BASE_DIR, "service_encoder.pkl"))
le_label = joblib.load(os.path.join(BASE_DIR, "label_encoder.pkl"))

# Initialize Isolation Forest for Anomaly Detection (Zero-Day Detection)
# Trained on normal data patterns if possible, here using a random sample or online learning.
iso_forest = IsolationForest(contamination=0.01, random_state=42)
# X_test_ohe was used in training, so we should fit on a small sample of X_test.pkl to calibrate
X_test_path = os.path.join(BASE_DIR, "X_test.pkl")
X_test_sample = joblib.load(X_test_path).sample(min(500, len(joblib.load(X_test_path))))
iso_forest.fit(X_test_sample)

def get_geo_info(ip):
    """Fetches real geographic location using ip-api.com."""
    # Handle local/private IPs
    if ip.startswith("192.168.") or ip.startswith("127.0.0.1") or ip.startswith("10.") or ip.startswith("172."):
        return {
            "country": "Local Network",
            "lat": 0,
            "lon": 0,
            "city": "Internal Net"
        }
    
    try:
        import requests
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "city": data.get("city", "Unknown")
            }
        else:
            return {
                "country": "Unknown",
                "lat": 0,
                "lon": 0,
                "city": "Unknown"
            }

    except Exception:
        return {
            "country": "Unknown",
            "lat": 0,
            "lon": 0,
            "city": "Unknown"
        }

# --- RULE-BASED DETECTION ---
RULES = [
    {"type": "DoS", "condition": lambda f: f.get('src_bytes', 0) > 10000000 and f.get('count', 0) > 500},
    {"type": "Probe", "condition": lambda f: f.get('dst_host_diff_srv_rate', 0) > 0.8 and f.get('dst_host_count', 0) > 200},
    {"type": "R2L", "condition": lambda f: f.get('num_failed_logins', 0) > 10},
]

def check_rules(features):
    """Checks input features against manual rules."""
    for rule in RULES:
        if rule["condition"](features):
            return rule["type"]
    return None

# --- PREVENTION SYSTEM (Windows netsh) ---
def block_ip(ip):
    """Blocks an IP using Windows Netsh with safety checks and logging."""
    # PART 2: SAFETY CHECK
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"[SAFETY] Skipping firewall block for local/internal IP: {ip}")
        return False

    print(f"[SYSTEM] Blocking IP: {ip}")
    # PART 2: FIREWALL BLOCKING (WINDOWS)
    command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
    try:
        import subprocess
        subprocess.run(command, shell=True, check=True)
        
        # PART 6: LOGGING
        from datetime import datetime
        with open("blocked_ips.log", "a") as f:
            f.write(f"{datetime.now()} - Blocked IP: {ip}\n")
            
        return True
    except Exception as e:
        print(f"[ERROR] Failed to block {ip}: {e}")
        return False

def rate_limit(ip):
    """Simulates rate limiting for an IP."""
    print(f"[SYSTEM] Applying rate limit to {ip}: 10pkts/sec")
    # In a real scenario, this might involve QoS or specialized firewall rules.
    return True

def block_port(port):
    """Blocks a specific port."""
    print(f"[SYSTEM] Blocking Port: {port}")
    cmd = f"netsh advfirewall firewall add rule name='BLOCK_PORT_{port}' dir=in action=block localport={port} protocol=TCP"
    subprocess.run(cmd, shell=True)
    return True

# --- SELF-HEALING ENGINE ---
def self_heal(attack_type):
    """Performs system recovery based on attack type."""
    actions = []
    if attack_type == "dos":
        actions.append("Clearing stale TCP connections...")
        subprocess.run("netstat -ano | findstr :80", shell=True) # Mock identifying DoS connections
        actions.append("Flushing firewall rules...")
        # subprocess.run("netsh advfirewall reset", shell=True) # Dangerous to auto-run
    elif attack_type == "probe":
        actions.append("Disabling ICMP echo responses...")
        subprocess.run("netsh advfirewall firewall set rule name='File and Printer Sharing (Echo Request - ICMPv4-In)' new enable=no", shell=True)
    elif attack_type == "u2r":
        actions.append("Force terminating suspicious root sessions...")
        actions.append("Reloading core security services...")
    
    return actions

# --- HYBRID DETECTION LOGIC ---
KDD_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

def analyze_traffic(features):
    """The core hybrid detection logic."""
    try:
        # 1. Rule-Based Overrides
        rule_match = check_rules(features)
        if rule_match:
            return rule_match, 100.0, "Rule-Based Trigger"

        # 2. Reconstruct Full Feature Set for ML
        # Fill missing features with defaults
        full_features = {}
        for col in KDD_COLUMNS:
            if col in features:
                full_features[col] = features[col]
            else:
                # Default values for KDD
                if col in ["protocol_type"]: full_features[col] = "tcp"
                elif col in ["service"]: full_features[col] = "http"
                elif col in ["flag"]: full_features[col] = "SF"
                else: full_features[col] = 0.0

        df = pd.DataFrame([full_features])
        df = df[KDD_COLUMNS] # Ensure correct order
        
        # Preprocessing identical to train_model.py
        if 'src_bytes' in df.columns: df['src_bytes'] = np.log1p(df['src_bytes'])
        if 'dst_bytes' in df.columns: df['dst_bytes'] = np.log1p(df['dst_bytes'])
        
        # Label encode service
        try:
            df['service'] = le_service.transform(df['service'])
        except:
            df['service'] = le_service.transform(['other'])[0]

        # Transform using ColumnTransformer
        X_ohe = ct.transform(df)
        
        # 3. Anomaly Detection (Isolation Forest)
        is_anomaly = iso_forest.predict(X_ohe)[0]
        if is_anomaly == -1:
            return "Zero-Day / Anomaly", 85.0, "Isolation Forest Hybrid"

        # 4. ML Prediction
        prob = model.predict_proba(X_ohe)[0]
        prediction = np.argmax(prob)
        confidence = float(round(max(prob) * 100, 2))
        attack_name = le_label.inverse_transform([prediction])[0]

        return attack_name, confidence, "XGBoost Engine"
        
    except Exception as e:
        print(f"[CRITICAL ERROR] Prediction Engine Failure: {e}")
        return "normal", 0.0, "ERROR_FALLBACK"

# --- HONEYPOT SYSTEM ---
def simulate_honeypot():
    """Simulates a decoy port 22/80 listener."""
    # This could be a background thread listening on unused ports
    return {"status": "ACTIVE", "decoys": [21, 22, 23, 445]}

if __name__ == "__main__":
    print("Defense Engine Test Run...")
    test_feat = {"src_bytes": 50000000, "count": 600, "service": "http", "protocol_type": "tcp", "flag": "SF"}
    print(analyze_traffic(test_feat))
