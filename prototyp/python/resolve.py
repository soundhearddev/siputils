import sys
import socket
from python.registry import load_registry, SUFFIX



def _is_valid_ipv6(addr: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except socket.error:
        return False

def _is_valid_ipv4(addr: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except socket.error:
        return False

def _dns_lookup(name: str) -> dict | None:
    try:
        results = socket.getaddrinfo(name, None, socket.AF_INET6)
        if results:
            ipv6 = results[0][4][0]
            return {"address": None, "ipv6": ipv6, "port": None, "source": "dns-ipv6"}
    except socket.gaierror:
        pass

    try:
        results = socket.getaddrinfo(name, None, socket.AF_INET)
        if results:
            ipv4 = results[0][4][0]
            return {"address": None, "ipv6": None, "ipv4": ipv4, "port": None, "source": "dns-ipv4"}
    except socket.gaierror:
        pass

    return None

def resolve(name: str, dns_fallback: bool = True) -> dict | None:
    if not name or not isinstance(name, str):
        return None

    name = name.strip().lower()

    if _is_valid_ipv6(name):
        return {"address": None, "ipv6": name, "port": None, "source": "direct-ipv6"}

    if _is_valid_ipv4(name):
        return {"address": None, "ipv6": None, "ipv4": name, "port": None, "source": "direct-ipv4"}

    reg = load_registry()

    if name in reg:
        return {**reg[name], "source": "registry"}

    if name.endswith(SUFFIX):
        without = name[:-len(SUFFIX)]
        if without in reg:
            return {**reg[without], "source": "registry"}

    if not name.endswith(SUFFIX):
        with_suffix = name + SUFFIX
        if with_suffix in reg:
            return {**reg[with_suffix], "source": "registry"}

    matches = [k for k in reg if k.startswith(name)]
    if len(matches) == 1:
        return {**reg[matches[0]], "source": "registry-partial", "matched": matches[0]}
    elif len(matches) > 1:
        return {"error": "ambiguous", "matches": matches, "source": None}

    if dns_fallback and not name.endswith(SUFFIX):
        result = _dns_lookup(name)
        if result:
            return result

    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Verwendung: python resolve.py <name>")
        print("\nAlle bekannten Domains:")
        reg = load_registry()
        if not reg:
            print("  (Registry leer)")
        for name, entry in reg.items():
            print(f"  {name:35s} → {entry.get('address','?')}  ({entry.get('ipv6','lokal')})")
        sys.exit(0)

    name   = sys.argv[1]
    result = resolve(name)

    if not result:
        print(f"[✗] {name} — nicht gefunden")
        sys.exit(1)

    if result.get("error") == "ambiguous":
        print(f"[?] Mehrdeutig — meintest du:")
        for m in result["matches"]:
            print(f"    {m}")
        sys.exit(1)

    print(f"[✓] {name}  (via {result['source']})")
    if result.get("matched"):
        print(f"    matched  : {result['matched']}")
    if result.get("address"):
        print(f"    mesh     : {result['address']}")
    if result.get("ipv6"):
        print(f"    ipv6     : {result['ipv6']}")
    if result.get("ipv4"):
        print(f"    ipv4     : {result['ipv4']}")
    if result.get("port"):
        print(f"    port     : {result['port']}")