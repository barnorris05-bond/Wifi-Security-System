import shutil
import sys

from scanner.base_scanner import BaseScanner, BackendUnavailableException
from scanner.iw_scanner import IWScanner
from scanner.iwlist_scanner import IWListScanner
from scanner.nmcli_scanner import NetworkManagerScanner
from scanner.windows_scanner import WindowsWLANScanner


class ScannerFactory:
    @staticmethod
    def get_scanner(interface: str = "Wi-Fi") -> BaseScanner:
        platform = sys.platform

        if platform == "win32":
            return WindowsWLANScanner(interface)

        backend_candidates = [
            ("nmcli", shutil.which("nmcli"), NetworkManagerScanner),
            ("iw", shutil.which("iw"), IWScanner),
            ("iwlist", shutil.which("iwlist"), IWListScanner),
        ]

        for backend_name, executable, scanner_cls in backend_candidates:
            if executable:
                return scanner_cls(interface)

        raise BackendUnavailableException(
            f"No supported wireless scanner backend found for platform '{platform}'. "
            "Install one of: nmcli, iw, or iwlist."
        )

    @staticmethod
    def get_backend_status(interface: str = "Wi-Fi"):
        platform = sys.platform
        if platform == "win32":
            return {"platform": "Windows", "interface": interface, "backend": "Windows netsh", "status": "Ready"}

        backend_candidates = [
            ("nmcli", shutil.which("nmcli")),
            ("iw", shutil.which("iw")),
            ("iwlist", shutil.which("iwlist")),
        ]

        for name, executable in backend_candidates:
            if executable:
                return {"platform": "Linux", "interface": interface, "backend": name, "status": "Ready"}

        return {"platform": "Linux", "interface": interface, "backend": None, "status": "Unavailable"}
