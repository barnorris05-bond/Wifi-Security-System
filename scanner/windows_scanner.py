import subprocess, uuid, time
from models.scan import ScanSession
from scanner.base_scanner import BaseScanner, ScannerException
from scanner.parsers.windows_parser import WindowsNetshParser

class WindowsWLANScanner(BaseScanner):
    def execute_scan(self) -> ScanSession:
        start_time = time.time()
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, check=True
            )
        except Exception as e:
            raise ScannerException(f"Windows Netsh scan failed: {str(e)}")

        networks = WindowsNetshParser().parse(result.stdout)
        duration = round(time.time() - start_time, 2)

        return ScanSession(
            scan_id=f"scan_{uuid.uuid4().hex[:8]}",
            interface=self.interface or "Wi-Fi",
            backend_used="netsh",
            duration_seconds=duration,
            networks=networks
        )
