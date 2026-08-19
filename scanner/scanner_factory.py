import sys, shutil
from scanner.base_scanner import BaseScanner, BackendUnavailableException
from scanner.windows_scanner import WindowsWLANScanner
from scanner.nmcli_scanner import NetworkManagerScanner
from scanner.iw_scanner import IWScanner
from scanner.iwlist_scanner import IWListScanner

class ScannerFactory:
    @staticmethod
    def get_scanner(interface: str = "Wi-Fi") -> BaseScanner:
        if sys.platform == "win32":
            return WindowsWLANScanner(interface)
        elif shutil.which("nmcli"):
            return NetworkManagerScanner(interface)
        elif shutil.which("iw"):
            return IWScanner(interface)
        elif shutil.which("iwlist"):
            return IWListScanner(interface)
        else:
            raise BackendUnavailableException("No supported wireless scanner backend found for OS platform.")
