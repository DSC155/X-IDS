import sqlite3
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "ids_logs.db")

def init_db():
    """Initializes the SQLite database with logs and blacklist tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Attack Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            source_ip TEXT,
            attack_type TEXT,
            confidence REAL,
            action_taken TEXT,
            severity TEXT
        )
    ''')
    
    # Blacklist Table for Threat Memory
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            attack_type TEXT,
            first_seen DATETIME,
            last_seen DATETIME,
            incident_count INTEGER,
            ban_until DATETIME,
            severity TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def log_attack(ip, attack_type, confidence, action_taken, severity):
    """Logs a detected attack to the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attack_logs (timestamp, source_ip, attack_type, confidence, action_taken, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (datetime.now(), ip, attack_type, confidence, action_taken, severity))
    
    # Update Blacklist
    cursor.execute('SELECT incident_count FROM blacklist WHERE ip = ?', (ip,))
    row = cursor.fetchone()
    if row:
        count = row[0] + 1
        # Adaptive ban: 10 mins * count^2
        ban_minutes = 10 * (count ** 2)
        ban_until = datetime.now().timestamp() + (ban_minutes * 60)
        cursor.execute('''
            UPDATE blacklist SET 
            last_seen = ?, 
            incident_count = ?, 
            ban_until = ?, 
            severity = ?
            WHERE ip = ?
        ''', (datetime.now(), count, datetime.fromtimestamp(ban_until), severity, ip))
    else:
        ban_until = datetime.now().timestamp() + (10 * 60) # Initial 10 min ban
        cursor.execute('''
            INSERT INTO blacklist (ip, attack_type, first_seen, last_seen, incident_count, ban_until, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip, attack_type, datetime.now(), datetime.now(), 1, datetime.fromtimestamp(ban_until), severity))
        
    conn.commit()
    conn.close()

def get_recent_attacks(limit=10):
    """Retrieves the most recent attack logs."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_blacklist():
    """Retrieves all currently blocked IPs."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM blacklist WHERE ban_until > ?', (datetime.now(),))
    rows = cursor.fetchall()
    conn.close()
    return rows

def is_blocked(ip):
    """Checks if an IP is currently in the blacklist and globally banned."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT ban_until FROM blacklist WHERE ip = ?', (ip,))
    row = cursor.fetchone()
    conn.close()
    if row:
        ban_until = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f') if isinstance(row[0], str) else row[0]
        if datetime.now() < ban_until:
            return True
    return False

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
