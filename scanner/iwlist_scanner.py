import subprocess, uuid, time
from models.scan import ScanSession
from scanner.base_scanner import BaseScanner, BackendUnavailableException, PermissionDeniedException, ScannerException
from scanner.parsers.iwlist_parser import IWListParser

class IWListScanner(BaseScanner):
    def execute_scan(self) -> ScanSession:
        start_time = time.time()
        try:
            result = subprocess.run(
                ['iwlist', self.interface, 'scanning'],
                capture_output=True, text=True, check=True
            )
        except FileNotFoundError:
            raise BackendUnavailableException("iwlist utility is missing on this system.")
        except subprocess.CalledProcessError as e:
            if "permission" in e.stderr.lower():
                raise PermissionDeniedException(f"Elevated rights required for iwlist scan on {self.interface}.")
            raise ScannerException(f"iwlist scan failed: {e.stderr.strip()}")

        networks = IWListParser().parse(result.stdout)
        duration = round(time.time() - start_time, 2)

        return ScanSession(
            scan_id=f"scan_{uuid.uuid4().hex[:8]}",
            interface=self.interface,
            backend_used="iwlist",
            duration_seconds=duration,
            networks=networks
        )
