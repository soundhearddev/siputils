import json
import os
import time
from datetime import datetime, timedelta

JSON_FILE = "addresses.json"

def load_storage() -> dict:
    default_structure = {"addresses": [], "sessions": {}}
    if not os.path.exists(JSON_FILE):
        return default_structure
    try:
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return default_structure
            if "addresses" not in data: data["addresses"] = []
            if "sessions" not in data: data["sessions"] = {}
            return data
    except json.JSONDecodeError:
        print(f"[!] Warnung: {JSON_FILE} war beschädigt. Erstelle neu.")
        return default_structure


def save_storage(data: dict):
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def log_new_address(address: str, iface: str, ttl: int = None, tag: str = "default"):
    db = load_storage()
    now = datetime.now()
    
    expires_at_str = None
    if ttl is not None:
        expires_at_str = (now + timedelta(seconds=ttl)).strftime("%Y-%m-%d %H:%M:%S")

    entry = {
        "address": address,
        "interface": iface,
        "tag": tag,
        "status": "active",
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "ttl_seconds": ttl,
        "expires_at": expires_at_str
    }
    
    db["addresses"].append(entry)
    save_storage(db)
    print(f"[💾] Adresse {address} in {JSON_FILE} protokolliert.")


def clean_expired_addresses():
    db = load_storage()
    now = datetime.now()
    changed = False
    
    for entry in db["addresses"]:
        if entry["status"] == "active" and entry["expires_at"]:
            expire_time = datetime.strptime(entry["expires_at"], "%Y-%m-%d %H:%M:%S")
            if now > expire_time:
                entry["status"] = "expired"
                changed = True
                
    session_timeout = 7200
    current_ts = time.time()
    to_delete = []
    
    for conn_id_str, session in db["sessions"].items():
        if current_ts - session["created"] > session_timeout:
            to_delete.append(conn_id_str)
            
    if to_delete:
        for k in to_delete:
            db["sessions"].pop(k, None)
        changed = True
        print(f"[💾] {len(to_delete)} abgelaufene Session(s) entfernt.")

    if changed:
        save_storage(db)



def store_session(conn_id: int, session_key: bytes, peer_mesh: str):
    db = load_storage()
    
    db["sessions"][str(conn_id)] = {
        "key_hex":   session_key.hex(),
        "peer_mesh": peer_mesh,
        "created":   time.time(),
        "created_at_str": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_storage(db)
    print(f"[💾] Session permanent gespeichert: {conn_id} ↔ {peer_mesh}")


def get_session(conn_id: int) -> dict | None:
    db = load_storage()
    session = db["sessions"].get(str(conn_id))
    
    if not session:
        return None
        
    session_copy = session.copy()
    session_copy["key"] = bytes.fromhex(session_copy["key_hex"])
    return session_copy


def remove_session(conn_id: int):
    db = load_storage()
    if str(conn_id) in db["sessions"]:
        db["sessions"].pop(str(conn_id), None)
        save_storage(db)
        print(f"[💾] Session {conn_id} aus JSON gelöscht.")