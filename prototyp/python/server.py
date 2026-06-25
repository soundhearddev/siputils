import json
import os
import socket
import threading
import time
from python.utils import load_env

from python.storage import get_session, store_session
from python.translation import peek_conn_id, receive

load_env()

HOST           = "::"
HANDSHAKE_PORT = 9998
MESH_PORT      = 9999

# ----------------------------
# Handler Registry
# ----------------------------
_json_handlers: dict[str, callable] = {}

def register_handler(msg_type: str, fn: callable):
    _json_handlers[msg_type] = fn

# ----------------------------
# Routing Logik
# ----------------------------
def _route_tcp(conn, addr):
    from translation import peek_conn_id
    
    with conn:
        try:
            data = conn.recv(65535)
            if not data:
                return

            conn_id = peek_conn_id(data)
            
            if conn_id is not None:
                _route_mesh(data, addr)
            else:
                try:
                    decoded_text = data.decode('utf-8', errors='strict')
                    msg = json.loads(decoded_text)
                    _route_json(conn, addr, msg)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    debug = os.environ.get("DEBUG", "").lower() in ("1", "true")
                    if debug:
                        print(f"[DEBUG] Binärdaten an JSON-Route abgefangen ({len(data)} Bytes).")
                    else:
                        print(f"[!] Ungültige oder unlesbare Daten von {addr[0]} (Kein gültiger Header/JSON)")
                    return

        except Exception as e:
            print(f"[!] Fehler bei TCP-Routing von {addr[0]}: {e}")
            

def _route_json(conn, addr, msg: dict):
    msg_type = msg.get("type")

    if not msg_type and "mesh_addr" in msg:
        _json_handlers["BOOTSTRAP"](conn, addr, msg)
        return

    handler = _json_handlers.get(msg_type)
    if handler:
        handler(conn, addr, msg)
    else:
        print(f"[!] Unbekannter Typ '{msg_type}' von {addr[0]}")
        conn.sendall(json.dumps({"ok": False, "reason": f"unknown type: {msg_type}"}).encode())

def _route_mesh(data: bytes, addr: tuple):
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true")

    conn_id = peek_conn_id(data)
    if debug: print(f"[DEBUG] Empfangene conn_id über peek: {conn_id}")

    if not conn_id:
        print(f"[!] Kein validen conn_id aus Paket von {addr[0]} lesbar.")
        return

    session = get_session(conn_id)
    if debug: print(f"[DEBUG] Geladene Session aus JSON: {session}")

    if not session:
        print(f"[!] Keine aktive Session für conn_id={conn_id} von {addr[0]} im Speicher.")
        return

    result = receive(data, addr, session["key"], conn_id)
    if result:
        _dispatch_payload(result, session, addr)

def _dispatch_payload(payload: bytes, session: dict, addr: tuple):
    print(f"[✓] Payload erfolgreich reassembliert von {addr[0]} ({len(payload)} Bytes):")
    print(f"    {payload[:128]}")

# ----------------------------
# UDP Mesh Routing
# ----------------------------
def _route_udp(data: bytes, addr: tuple):
    from translation import peek_conn_id
    
    conn_id = peek_conn_id(data)
    
    if conn_id is not None:
        _route_mesh(data, addr)
    else:
        print(f"[!] Ungültiges UDP-Paket von {addr[0]} (Kein MESH-Protokoll)")

# ----------------------------
# Netzwerk Listener (TCP & UDP)
# ----------------------------
def _tcp_listener():
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, HANDSHAKE_PORT))
        s.listen()
        print(f"[*] TCP Listener aktiv auf [::]:{HANDSHAKE_PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=_route_tcp, args=(conn, addr), daemon=True).start()

def _udp_listener():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, MESH_PORT))
        print(f"[*] UDP Listener aktiv auf [::]:{MESH_PORT}")
        while True:
            data, addr = s.recvfrom(65535)
            threading.Thread(target=_route_udp, args=(data, addr), daemon=True).start()

# ----------------------------
# Core-Handler Registrierung
# ----------------------------
def start():
    from registry import load_registry, save_registry, LOCAL_NAME

    def handle_bootstrap(conn, addr, msg):
        from bootstrap import build_handshake
        own_hs = build_handshake()
        conn.sendall(json.dumps(own_hs).encode())
        name = msg["name"]
        reg  = load_registry()
        reg[name] = {
            "address": msg["mesh_addr"],
            "pubkey":  msg["pubkey"],
            "ipv6":    addr[0],
            "port":    9998,
        }
        save_registry(reg)
        print(f"[+] Bootstrap erfolgreich: {name} → {msg['mesh_addr']}")

    def handle_session_hello(conn, addr, msg):
        from session import (gen_ephemeral, derive_session_key,
                             check_timestamp, verify_hello, sign_hello)
        from netIP import load_or_create_keys, load_public_key

        password    = os.environ.get("MESH_PASSWORD", "").encode()
        peer_mesh   = msg["mesh_addr"]
        
        conn_id = msg.get("conn_id")
        if conn_id is None:
            print(f"[!] Abbruch: Client von {addr[0]} hat keine conn_id gesendet.")
            conn.sendall(json.dumps({"type": "ERROR", "reason": "missing_conn_id"}).encode())
            return
        conn_id = int(conn_id)

        reg        = load_registry()
        peer_entry = next((e for e in reg.values() if e.get("address") == peer_mesh), None)

        if not peer_entry:
            conn.sendall(json.dumps({"type": "ERROR", "reason": "unknown peer"}).encode())
            return

        peer_pubkey = bytes.fromhex(peer_entry["pubkey"])
        b_pub       = bytes.fromhex(msg["ephemeral_pub"])
        challenge   = bytes.fromhex(msg["challenge"])
        ts          = msg["timestamp"]
        sig         = bytes.fromhex(msg["sig"])

        if not check_timestamp(ts):
            conn.sendall(json.dumps({"type": "ERROR", "reason": "timestamp expired"}).encode())
            return

        if not verify_hello(peer_pubkey, b_pub, challenge, ts, sig):
            conn.sendall(json.dumps({"type": "ERROR", "reason": "invalid signature"}).encode())
            return

        pub_bytes, _ = load_public_key()
        ed_priv, _   = load_or_create_keys(password)
        own_priv, own_pub = gen_ephemeral()
        own_ts       = time.time()
        own_sig      = sign_hello(ed_priv, own_pub, challenge, own_ts)

        conn.sendall(json.dumps({
            "type":          "SESSION_HELLO_ACK",
            "ephemeral_pub": own_pub.hex(),
            "sig":           own_sig.hex(),
            "timestamp":     own_ts,
        }).encode())

        session_key = derive_session_key(own_priv, b_pub)
        
        store_session(conn_id, session_key, peer_mesh)
        print(f"[✓] Session etabliert & synchronisiert: {peer_mesh} ↔ Conn ID: {conn_id}")

    register_handler("SESSION_HELLO", handle_session_hello)
    register_handler("mesh_addr",     handle_bootstrap)  
    register_handler("BOOTSTRAP",     handle_bootstrap)

    threading.Thread(target=_tcp_listener, daemon=True).start()
    threading.Thread(target=_udp_listener, daemon=True).start()
    
    print(f"[*] Server auf Knoten '{LOCAL_NAME}' erfolgreich gestartet. Warte auf Pakete...")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Server manuell gestoppt.")

if __name__ == "__main__":
    start()