import hashlib
import secrets
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from python.netIP import load_public_key, base_address, load_or_create_keys
from python.utils import load_env
import os
from python.storage import store_session, get_session, remove_session, clean_expired_addresses

load_env()
password = os.environ.get("MESH_PASSWORD", "").encode()

# ----------------------------
# Ephemeral Key
# ----------------------------
def gen_ephemeral() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    )
    return priv_raw, pub

def derive_session_key(own_priv: bytes, peer_pub_bytes: bytes) -> bytes:
    own      = X25519PrivateKey.from_private_bytes(own_priv)
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared   = own.exchange(peer_pub)
    return hashlib.sha256(shared).digest()

# ----------------------------
# Challenge + Timestamp
# ----------------------------
def gen_challenge() -> bytes:
    return secrets.token_bytes(32)

def check_timestamp(ts: float, window: int = 30) -> bool:
    return abs(time.time() - ts) <= window

# ----------------------------
# Signatur
# ----------------------------
def sign_hello(ed_priv: Ed25519PrivateKey, ephemeral_pub: bytes, challenge: bytes, timestamp: float) -> bytes:
    msg = ephemeral_pub + challenge + str(timestamp).encode()
    return ed_priv.sign(msg)

def verify_hello(ed_pub_bytes: bytes, ephemeral_pub: bytes, challenge: bytes, timestamp: float, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        msg = ephemeral_pub + challenge + str(timestamp).encode()
        Ed25519PublicKey.from_public_bytes(ed_pub_bytes).verify(sig, msg)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    pub_bytes, _  = load_public_key()
    own_mesh      = base_address(pub_bytes)
    ed_priv, _    = load_or_create_keys(password)
    conn_id       = int.from_bytes(secrets.token_bytes(8), "big")

    print(f"[*] Eigene mesh-addr : {own_mesh}")
    print(f"[*] Conn ID          : {conn_id}")

    a_priv, a_pub = gen_ephemeral()
    b_priv, b_pub = gen_ephemeral()

    challenge = gen_challenge()
    ts        = time.time()

    sig = sign_hello(ed_priv, a_pub, challenge, ts)
    valid = verify_hello(pub_bytes, a_pub, challenge, ts, sig)

    a_session = derive_session_key(a_priv, b_pub)
    b_session = derive_session_key(b_priv, a_pub)

    store_session(conn_id, a_session, "peer-mesh-addr")

    loaded_session = get_session(conn_id)
    if loaded_session:
        print(f"[✓] Session erfolgreich aus JSON geladen!")
        session_key_from_json = loaded_session["key"] 
        
        from translation import encrypt_fragment, decrypt_fragment
        msg       = b"Hallo Session Test ueber JSON"
        encrypted = encrypt_fragment(msg, session_key_from_json, conn_id)
        decrypted = decrypt_fragment(encrypted, b_session, conn_id)
        print(f"[✓] Korrekt entschlüsselt: {'JA ✔' if decrypted == msg else 'NEIN ❌'}")
        
    clean_expired_addresses()