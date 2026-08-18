from abc import ABC, abstractmethod
from models.scan import ScanSession

class ScannerException(Exception): pass
class PermissionDeniedException(ScannerException): pass
class BackendUnavailableException(ScannerException): pass

class BaseScanner(ABC):
    def __init__(self, interface: str):
        self.interface = interface

    @abstractmethod
    def execute_scan(self) -> ScanSession:
        pass
