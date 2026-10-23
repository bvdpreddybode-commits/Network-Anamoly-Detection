"""Live network capture using Scapy – runs in a background thread.
Windows: requires Npcap (https://npcap.com) and admin privileges.
"""
import threading, queue, time, logging, os, platform
import pandas as pd

log = logging.getLogger(__name__)

SCAPY_OK = False
NPCAP_OK = False

try:
    from scapy.all import sniff, conf, wrpcap
    SCAPY_OK = True
    # On Windows, check that Npcap/WinPcap driver is usable
    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            NPCAP_OK = True
        except Exception:
            NPCAP_OK = False
    else:
        NPCAP_OK = True          # Linux/Mac always ok
except Exception as e:
    log.warning("Scapy unavailable: %s", e)


def list_interfaces():
    """Return list of (display_name, scapy_name) tuples — only real, capturable interfaces."""
    if not SCAPY_OK:
        return []
    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            all_ifaces = get_windows_if_list()

            # Priority real adapters (these are the ones you can actually sniff)
            PRIORITY = ["Ethernet", "Wi-Fi", "VirtualBox", "Loopback"]
            # Skip filter/virtual driver noise
            SKIP_KEYWORDS = [
                "WFP", "QoS", "Filter", "Npcap Packet Driver",
                "Native WiFi Filter", "VirtualBox NDIS Light",
                "Virtual WiFi", "Wi-Fi Direct", "Miniport", "PPTP", "L2TP",
                "IKEv2", "SSTP", "6to4", "Teredo", "HTTPS",
                "Bluetooth", "PPPOE", "Kernel Debug", "eScan",
            ]

            result = []
            seen_names = set()
            for iface in all_ifaces:
                name = iface.get("name", "")
                desc = iface.get("description", name)
                if not name or name in seen_names:
                    continue
                # Skip noise adapters
                if any(kw.lower() in desc.lower() or kw.lower() in name.lower()
                       for kw in SKIP_KEYWORDS):
                    continue
                seen_names.add(name)
                result.append((f"{desc}  [{name}]", name))

            # Sort: put Ethernet, Wi-Fi first
            def sort_key(item):
                lbl = item[0].lower()
                for i, p in enumerate(["ethernet", "wi-fi", "virtualbox", "loopback"]):
                    if p in lbl:
                        return i
                return 99

            result.sort(key=sort_key)
            return result if result else []
        else:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            return [(i, i) for i in ifaces if i != "any"]
    except Exception as e:
        log.error("list_interfaces error: %s", e)
        return []


# Shared capture state — lives outside Streamlit session so the thread persists
_capture_lock   = threading.Lock()
_capture_thread = None          # type: threading.Thread | None
_capture_queue  = queue.Queue()
_stop_event     = threading.Event()
_capture_iface  = None
_error_msg      = None


def _sniffer(iface: str):
    global _error_msg
    try:
        sniff(
            iface=iface,
            prn=lambda pkt: _capture_queue.put(pkt),
            stop_filter=lambda _: _stop_event.is_set(),
            store=False,
        )
    except Exception as e:
        _error_msg = str(e)
        log.error("Capture error on %s: %s", iface, e)


def start_capture(iface: str):
    """Start background sniffer. Safe to call multiple times (no-op if already running)."""
    global _capture_thread, _capture_iface, _error_msg
    with _capture_lock:
        if _capture_thread and _capture_thread.is_alive():
            return  # already running
        _stop_event.clear()
        _error_msg = None
        _capture_iface = iface
        # Drain stale packets
        while not _capture_queue.empty():
            try: _capture_queue.get_nowait()
            except queue.Empty: break
        _capture_thread = threading.Thread(target=_sniffer, args=(iface,), daemon=True)
        _capture_thread.start()


def stop_capture():
    """Signal the sniffer thread to stop."""
    _stop_event.set()


def is_running() -> bool:
    return _capture_thread is not None and _capture_thread.is_alive()


def get_error() -> str | None:
    return _error_msg


def drain_packets() -> list:
    """Return all packets currently in the queue without blocking."""
    pkts = []
    try:
        while True:
            pkts.append(_capture_queue.get_nowait())
    except queue.Empty:
        pass
    return pkts


def packets_to_dataframe(packets: list) -> pd.DataFrame:
    """Convert a list of raw Scapy packets to the same DataFrame schema as parser."""
    if not packets:
        return pd.DataFrame()

    import sys, tempfile
    sys.path.insert(0, os.path.dirname(__file__))
    from parser import parse_pcap

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp = f.name
    try:
        wrpcap(tmp, packets)
        df = parse_pcap(tmp)
    finally:
        try: os.unlink(tmp)
        except: pass
    return df
