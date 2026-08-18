import shutil
from scanner.base_scanner import BaseScanner, BackendUnavailableException
from scanner.nmcli_scanner import NetworkManagerScanner
from scanner.iw_scanner import IWScanner
from scanner.iwlist_scanner import IWListScanner

class ScannerFactory:
    @staticmethod
    def get_scanner(interface: str) -> BaseScanner:
        if shutil.which("nmcli"):
            return NetworkManagerScanner(interface)
        elif shutil.which("iw"):
            return IWScanner(interface)
        elif shutil.which("iwlist"):
            return IWListScanner(interface)
        else:
            raise BackendUnavailableException("No supported wireless scanner backend found (nmcli, iw, iwlist).")
