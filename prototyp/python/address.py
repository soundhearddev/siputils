import sys
from python.storage import log_new_address

import utils

# ==============================================================================
# CONFIGURATION
# ==============================================================================
DEBUG = True               # True = Dummy-Interface (ipwrap0) | False = Live-Betrieb (Default-IF)
ANZAHL_IPS = 5             # Wie viele IPs generiert werden sollen
LEBENSDAUER_SEKUNDEN = 60  # TTL in Sekunden (Setze auf None für permanente IPs)

# ==============================================================================
# CORE LOGIC
# ==============================================================================

def build_address(count: int, prefix: str, before: set[str], iface: str, ttl: int = None) -> list[str]:
    created = []
    for _ in range(count):
        new_addr = utils.generate_address(prefix)
        while new_addr in before:
            new_addr = utils.generate_address(prefix)
        if utils.add_address(iface, new_addr, ttl=ttl):
            created.append(new_addr)  # ← neu
            before.add(new_addr)
            ttl_info = f" (TTL: {ttl}s)" if ttl else " (Permanent)"
            print(f"[✓] {new_addr}{ttl_info}")
            log_new_address(address=new_addr, iface=iface, ttl=ttl, tag="dev-test")
        else:
            print(f"[✗] Fehler bei {new_addr}")
    return created  



# ==============================================================================
# ADDRESS ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    utils.isroot()   

    if DEBUG:
        print("[MODUS] DEBUG-Modus aktiv. Nutze Dummy-Interface.")
        interface = utils.ensure_dummy_iface("ipwrap0")
    else:
        print("[MODUS] LIVE-Modus aktiv. Ermittle Standard-Interface...")
        interface = utils.get_default_iface()
        print(f"[i] Standard-Interface gefunden: {interface}")

    try:
        prefix = utils.get_prefix(interface)
    except SystemExit:
        if DEBUG:
            prefix = "2001:db8:1234:5678:"
            print(f"[i] Dummy hat kein Präfix. Verwende Test-Präfix: {prefix}")
        else:
            sys.exit(1)

    already_assigned = utils.current_addresses(interface)

    print(f"\nStarte Erstellung von {ANZAHL_IPS} Adressen auf '{interface}'...")
    build_address(
        count=ANZAHL_IPS, 
        prefix=prefix, 
        before=already_assigned, 
        iface=interface, 
        ttl=LEBENSDAUER_SEKUNDEN
    )