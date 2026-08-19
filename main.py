import argparse
import json

from scanner.interface import InterfaceManager
from scanner.scanner_factory import ScannerFactory


def main():
    parser = argparse.ArgumentParser(description="Run a Wi-Fi security scan.")
    parser.add_argument("--interface", default=None, help="Wi-Fi interface to scan")
    parser.add_argument("--json", action="store_true", help="Print scan output as JSON")
    args = parser.parse_args()

    iface = args.interface or InterfaceManager.get_default_interface() or "Wi-Fi"
    scanner = ScannerFactory.get_scanner(iface)
    session = scanner.execute_scan()

    if args.json:
        print(json.dumps(session.to_dict(), indent=2, default=str))
        return

    print(f"Scan on '{iface}' using {session.backend_used} found {len(session.networks)} networks.")
    for network in session.networks:
        print(f"- {network.ssid} ({network.bssid}) | {network.encryption} | ch{network.channel} | {network.band}")


if __name__ == "__main__":
    main()