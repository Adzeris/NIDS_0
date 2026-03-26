#!/usr/bin/env python3
"""
IP / ARP spoof detector.

Real-world detection methods:
  1. ARP cache poisoning — monitors ARP replies and alerts when an IP's MAC binding changes (classic MitM indicator).
  2. Bogon source filtering — flags packets from reserved/invalid IP ranges (loopback, multicast, link-local, documentation, etc.).
  3. TTL anomaly — builds a per-source TTL baseline and alerts when the TTL suddenly deviates beyond a threshold (suggests a different host
     is spoofing that source address).
"""

from scapy.all import sniff, ARP, IP, Ether
import time
import ipaddress
from collections import defaultdict, deque

from modules.firewall import ensure_chain, flush_chain, block_ip, ts
from modules.netutil import get_interface_ip, get_local_network, get_default_gateway

CHAIN = "NIDS_SPOOF"

_callback = None
_cfg = None
_defense_ip = None
_local_net = None
_gateway_ip = None
_safe_ips = set()

arp_table = {}
arp_cooldowns = {}
ttl_baselines = defaultdict(lambda: deque(maxlen=100))
ttl_alert_cooldowns = {}
blocked_ips = set()
_start_time = None

STANDARD_TTLS = {32, 64, 128, 255}

BOGON_NETS_BLOCK = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
]

BOGON_NETS_ALERT_ONLY = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
]

DHCP_SAFE = {
    ipaddress.ip_address("0.0.0.0"),
    ipaddress.ip_address("255.255.255.255"),
}

def set_callback(fn):
    global _callback
    _callback = fn


def _emit(msg):
    line = f"{ts()} {msg}"
    if _callback:
        _callback(line)
    else:
        print(line, flush=True)


def _classify_bogon(addr):
    """Classify an address: 'safe', 'block', 'alert', or None (clean)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if ip in DHCP_SAFE or addr in _safe_ips:
        return "safe"
    if any(ip in net for net in BOGON_NETS_BLOCK):
        return "block"
    if any(ip in net for net in BOGON_NETS_ALERT_ONLY):
        return "alert"
    return None


def _block(src, reason):
    if src not in blocked_ips:
        block_ip(CHAIN, src)
        blocked_ips.add(src)
        _emit(f"[BLOCK] Blocked {src} ({reason})")


def _handle_arp(pkt):
    """Detect ARP cache poisoning (IP→MAC binding changes)."""
    if not _cfg["spoof"].get("arp_watch", True):
        return

    if pkt[ARP].op != 2:  # only ARP replies (is-at)
        return

    src_ip = pkt[ARP].psrc
    src_mac = pkt[Ether].src.upper()
    cooldown = _cfg["spoof"].get("arp_alert_cooldown", 30)

    if src_ip in _safe_ips or src_ip == _defense_ip:
        return

    now = time.time()

    if src_ip in arp_table:
        old_mac = arp_table[src_ip]
        if old_mac != src_mac:
            cooldown_key = f"{src_ip}:{src_mac}"
            if cooldown_key not in arp_cooldowns or (now - arp_cooldowns[cooldown_key]) > cooldown:
                _emit(
                    f"[ALERT] ARP spoof detected: {src_ip} changed "
                    f"from {old_mac} → {src_mac} (possible MitM)"
                )
                arp_cooldowns[cooldown_key] = now
                _block(src_ip, "ARP poisoning")

    arp_table[src_ip] = src_mac


def _nearest_initial_ttl(ttl):
    """Map an observed TTL to its likely initial value (OS fingerprint)."""
    for init in sorted(STANDARD_TTLS):
        if ttl <= init:
            return init
    return 255


def _handle_ip(pkt):
    """Detect bogon sources and TTL anomalies."""
    src = pkt[IP].src
    now = time.time()

    if src == _defense_ip or src in blocked_ips or src in _safe_ips:
        return

    bogon_class = _classify_bogon(src)
    if bogon_class == "safe":
        return
    if bogon_class == "block":
        _emit(f"[ALERT] Bogon source detected: {src}")
        _block(src, "bogon address")
        return
    if bogon_class == "alert":
        _emit(f"[INFO] Bogon-range traffic from {src} (alert only, not blocked)")
        return

    ttl = pkt[IP].ttl
    if ttl <= 1 or ttl == 255:
        return

    deviation = _cfg["spoof"].get("ttl_deviation", 15)
    min_samples = _cfg["spoof"].get("ttl_min_samples", 10)
    cooldown = _cfg["spoof"].get("arp_alert_cooldown", 30)

    initial_ttl = _nearest_initial_ttl(ttl)
    history = ttl_baselines[src]
    history.append(initial_ttl)

    if len(history) < min_samples:
        return

    from collections import Counter
    counts = Counter(history)
    dominant_ttl, _ = counts.most_common(1)[0]

    if initial_ttl != dominant_ttl and abs(ttl - dominant_ttl) > deviation:
        if src not in ttl_alert_cooldowns or (now - ttl_alert_cooldowns[src]) > cooldown:
            _emit(
                f"[ALERT] TTL anomaly from {src}: "
                f"got {ttl} (init {initial_ttl}), expected ~{dominant_ttl} "
                f"— possible spoof"
            )
            ttl_alert_cooldowns[src] = now


def _on_packet(pkt):
    now = time.time()
    if now - _start_time < 3:
        return

    if pkt.haslayer(ARP):
        _handle_arp(pkt)
    if pkt.haslayer(IP):
        _handle_ip(pkt)


def run_detector(cfg, stop_event=None):
    """Main loop — runs until stop_event is set."""
    global _cfg, _defense_ip, _local_net, _gateway_ip, _safe_ips, _start_time

    _cfg = cfg
    iface = cfg["interface"]
    _defense_ip = get_interface_ip(iface)
    _local_net = get_local_network(iface)
    _gateway_ip = get_default_gateway(iface)
    _start_time = time.time()

    _safe_ips = {"0.0.0.0", "255.255.255.255"}
    if _gateway_ip:
        _safe_ips.add(_gateway_ip)
    for ip_str in cfg["spoof"].get("whitelist_ips", []):
        _safe_ips.add(ip_str.strip())

    arp_table.clear()
    arp_cooldowns.clear()
    ttl_baselines.clear()
    ttl_alert_cooldowns.clear()
    blocked_ips.clear()

    ensure_chain(CHAIN)
    flush_chain(CHAIN)

    _emit(f"[START] Spoof detector on {iface} (IP: {_defense_ip}, subnet: {_local_net})")
    if _gateway_ip:
        _emit(f"[INFO] Gateway {_gateway_ip} auto-whitelisted")
    _emit(f"[INFO] ARP watch: {cfg['spoof'].get('arp_watch', True)}, "
          f"TTL deviation threshold: {cfg['spoof'].get('ttl_deviation', 15)}, "
          f"blocks persist until NIDS stops")

    try:
        while stop_event is None or not stop_event.is_set():
            sniff(
                iface=iface,
                prn=_on_packet,
                store=False,
                timeout=2,
                stop_filter=lambda _: stop_event is not None and stop_event.is_set(),
            )
    finally:
        flush_chain(CHAIN)
        _emit("[STOP] Spoof detector stopped")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
