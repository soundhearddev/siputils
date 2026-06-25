import socket
import json
from python.netIP import load_public_key, base_address
from python.registry import load_registry, LOCAL_NAME
from python.utils import load_env

from python.storage import load_storage, get_session
from python.translation import translate_outbound

load_env()

def pick_peer() -> tuple[str, dict] | tuple[None, None]:
    reg   = load_registry()
    peers = {k: v for k, v in reg.items() if k != LOCAL_NAME}

    if not peers:
        print("[!] Keine Peers in Registry")
        return None, None

    listed = list(peers.items())
    for i, (name, entry) in enumerate(listed):
        print(f"  [{i}] {name:35s} ipv6:{entry.get('ipv6','?')}")

    try:
        idx = int(input("\nPeer wählen [Nummer]: "))
        return listed[idx]
    except (ValueError, IndexError):
        print("[!] Ungültige Auswahl")
        return None, None

if __name__ == "__main__":
    pub_bytes, _ = load_public_key()
    src          = base_address(pub_bytes)

    peer_name, peer = pick_peer()
    if not peer:
        exit(1)

    dst      = peer["address"]
    dst_ipv6 = peer["ipv6"]
    port     = peer.get("port", 9998)

    conn_id = None
    db = load_storage()
    matching_sessions = []

    for cid_str, session in db.get("sessions", {}).items():
        if session.get("peer_mesh") == dst:
            matching_sessions.append((session.get("created", 0), cid_str))

    if matching_sessions:
        matching_sessions.sort()
        conn_id = int(matching_sessions[-1][1])
        print(f"[✓] Aktive (neueste) Session in JSON gefunden! Conn ID: {conn_id}")
    else:
        print(f"[!] Keine aktive Session für {peer_name} in JSON gefunden.")
        print("[!] Bitte führe zuerst main_session.py aus!")
        exit(1)

    session_data = get_session(conn_id)
    if not session_data:
        print(f"[!] Fehler: Session-Key für ID {conn_id} konnte nicht geladen werden.")
        exit(1)
    
    session_key = session_data["key"]  


    payload = json.dumps({"cmd": "NEGOTIATE", "paths": 4}).encode()

    outbound_packets = translate_outbound(payload, src, dst, session_key, [dst_ipv6], conn_id)

    print(f"\n[*] Sende an {peer_name} [{dst_ipv6}]:{port}")
    print(f"[*] Anzahl Fragmente: {len(outbound_packets)}")

    for enc_packet, target_ip in outbound_packets:

        print(f"[*] Sende Fragment ({len(enc_packet)} Bytes) an [{target_ip}]:{port}...")
        
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((target_ip, port))
                s.sendall(enc_packet) 
                print(f"[✓] Fragment erfolgreich gesendet")

                s.settimeout(2)
                try:
                    response = s.recv(65535)
                    if response:
                        print(f"[<] Antwort von Server: {response}")
                except socket.timeout:
                    pass
        except Exception as e:
            print(f"[!] Fehler beim Senden an {target_ip}: {e}")