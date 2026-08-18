import subprocess, uuid, time
from models.scan import ScanSession
from scanner.base_scanner import BaseScanner, BackendUnavailableException, PermissionDeniedException, ScannerException
from scanner.parsers.iw_parser import IWParser

class IWScanner(BaseScanner):
    def execute_scan(self) -> ScanSession:
        start_time = time.time()
        try:
            result = subprocess.run(
                ['iw', 'dev', self.interface, 'scan'],
                capture_output=True, text=True, check=True
            )
        except FileNotFoundError:
            raise BackendUnavailableException("iw utility is missing on this system.")
        except subprocess.CalledProcessError as e:
            if "permission" in e.stderr.lower():
                raise PermissionDeniedException(f"Elevated rights required for iw scan on {self.interface}.")
            raise ScannerException(f"iw scan failed: {e.stderr.strip()}")

        networks = IWParser().parse(result.stdout)
        duration = round(time.time() - start_time, 2)

        return ScanSession(
            scan_id=f"scan_{uuid.uuid4().hex[:8]}",
            interface=self.interface,
            backend_used="iw",
            duration_seconds=duration,
            networks=networks
        )
