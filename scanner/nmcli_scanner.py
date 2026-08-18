import subprocess, uuid, time
from models.scan import ScanSession
from scanner.base_scanner import BaseScanner, BackendUnavailableException, PermissionDeniedException, ScannerException
from scanner.parsers.nmcli_parser import NMCLIParser

class NetworkManagerScanner(BaseScanner):
    def execute_scan(self) -> ScanSession:
        start_time = time.time()
        try:
            result = subprocess.run(
                ['nmcli', '-f', 'BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY', 'device', 'wifi', 'list', '--rescan', 'yes'],
                capture_output=True, text=True, check=True
            )
        except FileNotFoundError:
            raise BackendUnavailableException("nmcli utility is missing on this system.")
        except subprocess.CalledProcessError as e:
            if "permission" in e.stderr.lower():
                raise PermissionDeniedException("Elevated rights required for nmcli scan.")
            raise ScannerException(f"nmcli scan failed: {e.stderr.strip()}")

        networks = NMCLIParser().parse(result.stdout)
        duration = round(time.time() - start_time, 2)

        return ScanSession(
            scan_id=f"scan_{uuid.uuid4().hex[:8]}",
            interface=self.interface,
            backend_used="nmcli",
            duration_seconds=duration,
            networks=networks
        )
