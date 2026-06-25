import json
import socket
from python.netIP import load_public_key, base_address
from python.registry import SUFFIX, DEFAULT_PORT, LOCAL_NAME

HANDSHAKE_PORT = 9998

def build_handshake() -> dict:
    pub_bytes, _ = load_public_key()
    return {
        "mesh_addr": base_address(pub_bytes),
        "pubkey":    pub_bytes.hex(),
        "port":      DEFAULT_PORT,
        "name":  LOCAL_NAME,
    }

def bootstrap(target_ipv6: str):
    hs     = build_handshake()
    packet = json.dumps(hs).encode()

    print(f"[*] Verbinde zu {target_ipv6}:{HANDSHAKE_PORT}...")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        try:
            s.connect((target_ipv6, HANDSHAKE_PORT))
        except socket.timeout:
            print(f"[!] Timeout — {target_ipv6} nicht erreichbar")
            return None, None
        except ConnectionRefusedError:
            print(f"[!] Verbindung abgelehnt — läuft server.py auf {target_ipv6}?")
            return None, None

        print(f"[*] Verbunden — sende Handshake ({len(packet)} Bytes)...")
        s.sendall(packet)

        print(f"[*] Warte auf Antwort...")
        response = s.recv(65535)

    if not response:
        print(f"[!] Keine Antwort erhalten")
        return None, None

    peer_hs = json.loads(response.decode())

    from registry import load_registry, save_registry
    reg = load_registry()
    reg[peer_hs["name"]] = {
        "address": peer_hs["mesh_addr"],
        "pubkey":  peer_hs["pubkey"],
        "ipv6":    target_ipv6,
        "port":    peer_hs["port"],
    }
    save_registry(reg)

    print(f"[<] Handshake empfangen von {peer_hs['name']}")
    print(f"    mesh : {peer_hs['mesh_addr']}")
    print(f"    ipv6 : {target_ipv6}:{peer_hs['port']}")
    return peer_hs, target_ipv6

if __name__ == "__main__":
    import sys
    if "--bootstrap" in sys.argv:
        i = sys.argv.index("--bootstrap")
        peer_hs, ipv6 = bootstrap(sys.argv[i + 1])
        print(json.dumps(peer_hs, indent=2))
    else:
        print(json.dumps(build_handshake(), indent=2))