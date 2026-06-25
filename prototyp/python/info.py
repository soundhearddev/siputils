import subprocess
import netifaces

def get_network_info():
    interfaces = {}

    for iface in netifaces.interfaces():
        if iface == "lo":
            continue

        addrs = netifaces.ifaddresses(iface)

        ipv6_list = []
        for a in addrs.get(netifaces.AF_INET6, []):
            addr = a["addr"].split("%")[0]
            if not addr.startswith("fe80"):
                ipv6_list.append(addr)

        interfaces[iface] = {
            "ipv6": ipv6_list or None,
            "gateway_ipv6": None,
        }
        


    result = subprocess.run(["ip", "-6", "route"], capture_output=True, text=True)
    
    for line in result.stdout.splitlines():
        if line.startswith("default"):
            parts = line.split()
            gw = parts[2]
            dev_index = parts.index("dev") + 1 if "dev" in parts else None
            if dev_index:
                dev = parts[dev_index]
                if dev in interfaces:
                    interfaces[dev]["gateway_ipv6"] = gw
    return interfaces

net = get_network_info()



seen = set()

for iface, info in net.items():
    for addr in info.get("ipv6") or []:
        addr = addr.split("%")[0]

        if addr.startswith("fe80"):
            continue

        if addr not in seen:
            seen.add(addr)
            print(addr)


