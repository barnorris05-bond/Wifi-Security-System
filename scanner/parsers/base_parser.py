import warnings
from abc import ABC, abstractmethod
from typing import List, Optional

from models.network import NetworkModel

HIDDEN_SSID = "<Hidden SSID>"


class ParserWarning(UserWarning):
    """Warning raised when a parser encounters malformed or partial Wi-Fi data."""


class BaseParser(ABC):
    HIDDEN_SSID = HIDDEN_SSID

    @abstractmethod
    def parse(self, raw_output: str) -> List[NetworkModel]:
        pass

    @staticmethod
    def calculate_percent(dbm: Optional[int]) -> int:
        if dbm is None:
            return 0
        if dbm <= -100:
            return 0
        if dbm >= -30:
            return 100
        return int(2 * (dbm + 100))

    @staticmethod
    def warn(message: str):
        warnings.warn(message, ParserWarning, stacklevel=2)

    @staticmethod
    def safe_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
