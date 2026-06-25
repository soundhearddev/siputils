import subprocess
import secrets
import os
import sys
import re
from socket import gethostname
import hashlib
import time
from python.header import MAGIC
import struct


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def get_hostname():
    hostname = gethostname()
    

def isroot():
    if os.geteuid() != 0:
        print("✗ Bitte als root / mit sudo ausführen.")
        sys.exit(1)


def get_default_iface() -> str:
    r = run(["ip", "-6", "route", "show", "default"])
    for line in r.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    print("✗ Kein Default-Interface gefunden.")
    sys.exit(1)


def ensure_dummy_iface(name="ipwrap0") -> str:
    r = run(["ip", "link", "show", name])
    if r.returncode != 0:
        r = run(["ip", "link", "add", name, "type", "dummy"])
        if r.returncode != 0:
            print("✗ Konnte Interface nicht erstellen:", r.stderr.strip())
            sys.exit(1)
    run(["ip", "link", "set", name, "up"])
    return name


def expand_ipv6(addr: str) -> str:
    if "::" in addr:
        left, right = addr.split("::", 1)
        l = left.split(":") if left else []
        r = right.split(":") if right else []
        missing = 8 - len(l) - len(r)
        groups = l + ["0000"] * missing + r
    else:
        groups = addr.split(":")
    return ":".join(g.zfill(4) for g in groups)


def get_prefix(iface: str) -> str:
    r = run(["ip", "-o", "-6", "addr", "show", "dev", iface])
    for line in r.stdout.splitlines():
        if "scope global" not in line:
            continue
        m = re.search(r"inet6 ([0-9a-f:]+)/(\d+)", line)
        if not m:
            continue
        addr, plen = m.group(1), int(m.group(2))
        if plen > 64:
            continue
        full = expand_ipv6(addr)
        groups = full.split(":")
        return ":".join(groups[:4]) + ":"
    print(f"✗ Kein globales IPv6-Prefix auf Interface '{iface}' gefunden.")
    sys.exit(1)


def random_suffix() -> str:
    return ":".join(f"{secrets.randbits(16):04x}" for _ in range(4))


def generate_address(prefix: str) -> str:
    return prefix + random_suffix()


def current_addresses(iface: str) -> set[str]:
    r = run(["ip", "-o", "-6", "addr", "show", "dev", iface])
    addresses = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[3].split("/")[0]
            addresses.add(expand_ipv6(ip))
    return addresses


def add_address(iface: str, addr: str, ttl: int = None) -> bool:
    cmd = ["ip", "-6", "addr", "add", f"{addr}/64", "dev", iface]
    
    if ttl is not None:
        cmd.extend(["valid_lft", str(ttl), "preferred_lft", str(ttl)])
    
    r = run(cmd)
    if r.returncode != 0 and "File exists" not in r.stderr:
        print("[DEBUG ip error]", r.stderr.strip())
        
    return r.returncode == 0






def gen_conn_id(pub_bytes: bytes, ts: int) -> int:
    data = pub_bytes + ts.to_bytes(8, "big")
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest[:8], "big")


REGISTRY_FILE = "./local_registry.json"
DEFAULT_PORT  = 9999


def build_packet(src_mesh: str, dst_mesh: str, payload: bytes) -> bytes:
    return (
            struct.pack("!I", MAGIC) +
            bytes.fromhex(src_mesh) +
            bytes.fromhex(dst_mesh) +
            len(payload).to_bytes(2, "big") +
            payload
        )
    
def parse_packet(data: bytes) -> dict | None:    
    if len(data) < 36 or data[:4] != struct.pack("!I", MAGIC):
            return None
    src     = data[4:20].hex()
    dst     = data[20:36].hex()
    length  = int.from_bytes(data[36:38], "big")
    payload = data[38:38 + length]
    return {"src": src, "dst": dst, "payload": payload}


def load_env(path=".env"):
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip()
    except FileNotFoundError:
        pass