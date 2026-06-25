import os
import stat
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from python.utils import load_env

load_env()
password = os.environ.get("MESH_PASSWORD", "").encode()


KEY_DIR = "./keys"
PRIVATE_FILE = os.path.join(KEY_DIR, "private.key")
PUBLIC_FILE  = os.path.join(KEY_DIR, "public.key")

ED25519_KEY_SIZE   = 32
HMAC_DERIVE_LENGTH = 32

def _open_secure(path: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "wb")

def _check_permissions(path: str) -> None:
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"{path} ist zu offen ({oct(mode)}). Erwartet: 0o600."
        )

def load_or_create_keys(password: bytes) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    os.makedirs(KEY_DIR, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)

    if os.path.exists(PRIVATE_FILE) and os.path.exists(PUBLIC_FILE):
        return load_keys(password)  
    return create_keys(password)    

def create_keys(password: bytes) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    raw_priv = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    encrypted_priv = _encrypt_key(raw_priv, password)

    with _open_secure(PRIVATE_FILE) as f:
        f.write(encrypted_priv)
    with _open_secure(PUBLIC_FILE) as f:
        f.write(raw_pub)

    return private_key, public_key

def load_keys(password: bytes) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    _check_permissions(PRIVATE_FILE)
    _check_permissions(PUBLIC_FILE)

    with open(PRIVATE_FILE, "rb") as f:
        encrypted_priv = f.read()
    with open(PUBLIC_FILE, "rb") as f:
        pub_bytes = f.read()

    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError(f"Public Key hat ungültige Länge: {len(pub_bytes)}")

    raw_priv = _decrypt_key(encrypted_priv, password)
    if len(raw_priv) != ED25519_KEY_SIZE:
        raise ValueError(f"Private Key hat ungültige Länge nach Entschlüsselung: {len(raw_priv)}")

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
    pub  = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    return priv, pub


def load_public_key() -> tuple[bytes, ed25519.Ed25519PublicKey]:
    _check_permissions(PUBLIC_FILE)
    with open(PUBLIC_FILE, "rb") as f:
        pub_bytes = f.read()
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError(f"Public Key hat ungültige Länge: {len(pub_bytes)}")
    return pub_bytes, ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

def _derive_aes_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations=600_000, dklen=32)

def _encrypt_key(raw_key: bytes, password: bytes) -> bytes:
    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    aes_key = _derive_aes_key(password, salt)
    ct = AESGCM(aes_key).encrypt(nonce, raw_key, None)
    return salt + nonce + ct

def _decrypt_key(blob: bytes, password: bytes) -> bytes:
    if len(blob) < 16 + 12 + ED25519_KEY_SIZE + 16:  
        raise ValueError("Verschlüsselter Key-Blob ist zu kurz.")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    aes_key = _derive_aes_key(password, salt)
    return AESGCM(aes_key).decrypt(nonce, ct, None) 

def base_address(pub_bytes: bytes) -> str:
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError("Ungültige Public-Key-Länge.")
    return hashlib.sha256(pub_bytes).hexdigest()[:HMAC_DERIVE_LENGTH]

def derive_address(master_secret: bytes, index: bytes, nonce: bytes) -> str:
    msg = len(index).to_bytes(2, "big") + index + nonce
    return hmac.new(master_secret, msg, hashlib.sha256).hexdigest()[:HMAC_DERIVE_LENGTH]

def gen_id(pub_bytes: bytes, length: int = 32) -> str:
    if length <= 0:
        raise ValueError("length muss > 0 sein")
    if len(pub_bytes) != ED25519_KEY_SIZE:
        raise ValueError("Ungültige Public-Key-Länge")

    nonce = secrets.token_bytes(16)  
    digest = hashlib.sha256(pub_bytes + nonce).hexdigest()

    return digest[:length]


if __name__ == "__main__":
    
    master_secret = secrets.token_bytes(32)   
    nonce = secrets.token_bytes(16)           


    
    priv, pub = load_or_create_keys(password)
    pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    print("Standard:", base_address(pub_bytes))
    # for i in range(5):
    #     addr = derive_address(master_secret, i.to_bytes(4, "big"), nonce)
    #     print(f"[{i}]", addr)