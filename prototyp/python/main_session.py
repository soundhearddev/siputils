import os
import secrets
import socket
from python.utils import load_env
from python.registry import load_registry, LOCAL_NAME
from python.resolve import resolve
from python.netIP import load_or_create_keys, load_public_key, base_address

from python.session import (
    gen_ephemeral, derive_session_key,
    gen_challenge, check_timestamp,
    sign_hello, verify_hello,
    store_session, get_session
)

load_env()
PASSWORD = os.environ.get("MESH_PASSWORD", "").encode()

def pick_peer() -> tuple[str, dict] | tuple[None, None]:
    reg = load_registry()
    peers = {k: v for k, v in reg.items() if k != LOCAL_NAME}

    if not peers:
        print("[!] Keine Peers in Registry — erst bootstrap ausführen")
        return None, None

    print("\nBekannte Peers:")
    listed = list(peers.items())
    for i, (name, entry) in enumerate(listed):
        print(f"  [{i}] {name:35s} mesh:{entry.get('address','?')[:16]}...  ipv6:{entry.get('ipv6','?')}")

    try:
        idx = int(input("\nPeer wählen [Nummer]: "))
        name, entry = listed[idx]
        return name, entry
    except (ValueError, IndexError):
        print("[!] Ungültige Auswahl")
        return None, None

def build_session(peer_name: str, peer_entry: dict) -> int | None:
    print(f"\n[*] Starte Session-Aufbau mit {peer_name}...")

    pub_bytes, _  = load_public_key()
    ed_priv, _    = load_or_create_keys(PASSWORD)
    own_mesh      = base_address(pub_bytes)

    peer_mesh     = peer_entry.get("address")
    peer_pubkey   = bytes.fromhex(peer_entry.get("pubkey", ""))
    peer_ipv6     = peer_entry.get("ipv6")
    peer_port     = peer_entry.get("port", 9998) 

    if not peer_ipv6 or not peer_pubkey:
        print("[!] Peer hat keine IPv6 oder pubkey in Registry")
        return None

    conn_id = int.from_bytes(secrets.token_bytes(8), "big")

    a_priv, a_pub = gen_ephemeral()
    challenge     = gen_challenge()
    import time; ts = time.time()

    sig = sign_hello(ed_priv, a_pub, challenge, ts)
    print(f"[*] Generierte Conn ID: {conn_id}")
    print(f"[*] Ephemeral pub     : {a_pub.hex()[:32]}...")
    print(f"[*] Signatur          : {sig.hex()[:32]}...")

    print(f"[*] Verbinde zu [{peer_ipv6}]:{peer_port}...")
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((peer_ipv6, peer_port))

            import json
            hello = json.dumps({
                "type":         "SESSION_HELLO",
                "mesh_addr":    own_mesh,
                "ephemeral_pub": a_pub.hex(),
                "challenge":    challenge.hex(),
                "timestamp":    ts,
                "sig":          sig.hex(),
                "conn_id":      conn_id, 
            }).encode()

            s.sendall(hello)
            print(f"[*] HELLO gesendet — warte auf ACK...")

            response = json.loads(s.recv(65535).decode())

            if response.get("type") != "SESSION_HELLO_ACK":
                print(f"[!] Unerwartete Antwort vom Server: {response.get('type')}")
                if "reason" in response:
                    print(f"[!] Server-Begründung: {response['reason']}")
                return None

            b_pub     = bytes.fromhex(response["ephemeral_pub"])
            b_sig     = bytes.fromhex(response["sig"])
            b_ts      = response["timestamp"]

            if not check_timestamp(b_ts):
                print("[!] Timestamp des Servers abgelaufen")
                return None

            if not verify_hello(peer_pubkey, b_pub, challenge, b_ts, b_sig):
                print("[!] Signatur des Servers ungültig")
                return None

            print(f"[✓] Server-Signatur gültig")

            session_key = derive_session_key(a_priv, b_pub)
            
            store_session(conn_id, session_key, peer_mesh)

            print(f"[✓] Session Key   : {session_key.hex()[:32]}...")
            print(f"[✓] Conn ID       : {conn_id}")
            print(f"[✓] Session aktiv mit {peer_name} (Permanent in JSON gespeichert)")
            return conn_id

    except socket.timeout:
        print(f"[!] Timeout — {peer_ipv6} nicht erreichbar")
    except ConnectionRefusedError:
        print(f"[!] Verbindung abgelehnt — läuft server.py auf der Gegenseite?")
    except Exception as e:
        print(f"[!] Unbekannter Fehler während des Handshakes: {e}")

    return None

if __name__ == "__main__":
    print(f"[*] Eigene Adresse: {LOCAL_NAME}")

    peer_name, peer_entry = pick_peer()
    if peer_name:
        conn_id = build_session(peer_name, peer_entry)
        if conn_id:
            print(f"\n[✓] Handshake erfolgreich! (ID: {conn_id})")
            print("[*] Du kannst jetzt test_send.py ausführen, um Daten zu senden.")
        else:
            print("\n[✗] Session-Aufbau fehlgeschlagen.")