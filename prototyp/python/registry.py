import json
import socket
from pathlib import Path
from python.netIP import load_or_create_keys, base_address, load_public_key
from cryptography.hazmat.primitives import serialization
import secrets
import os
from python.utils import load_env

REGISTRY_FILE = "./local_registry.json"
STATE_FILE    = "./node_state.json"
SUFFIX        = ".mesh"
DEFAULT_PORT = 9998

def _build_local_name() -> str:
    pub_bytes, _ = load_public_key()
    suffix = base_address(pub_bytes)[-4:]
    return f"{socket.gethostname()}-{suffix}{SUFFIX}"

LOCAL_NAME = _build_local_name()

def load_or_create_state() -> tuple[bytes, bytes]:
    if Path(STATE_FILE).exists():
        s = json.loads(Path(STATE_FILE).read_text())
        return bytes.fromhex(s["master_secret"]), bytes.fromhex(s["nonce"])
    master_secret = secrets.token_bytes(32)
    nonce         = secrets.token_bytes(16)
    fd = os.open(STATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"master_secret": master_secret.hex(), "nonce": nonce.hex()}, f)
    return master_secret, nonce

def load_registry() -> dict:
    if Path(REGISTRY_FILE).exists():
        return json.loads(Path(REGISTRY_FILE).read_text())
    return {}

def save_registry(reg: dict):
    Path(REGISTRY_FILE).write_text(json.dumps(reg, indent=2))

def register(name: str, address: str):
    reg = load_registry()
    reg[name] = {"address": address}
    save_registry(reg)
    print(f"[+] {name} → {address}")

def resolve(name: str) -> str | None:
    return (load_registry().get(name) or {}).get("address")

if __name__ == "__main__":
    load_env()
    password = os.environ.get("MESH_PASSWORD", "").encode()
    
    priv, pub = load_or_create_keys(password)
    pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    master_secret, nonce = load_or_create_state() 

    std_addr = base_address(pub_bytes)
    hostname = socket.gethostname()

    register(LOCAL_NAME,  std_addr)
    
    print("\n--- Resolution ---")
    
    result = resolve(LOCAL_NAME)
    print(f"  {LOCAL_NAME:30s} → {result or 'NICHT GEFUNDEN'}")