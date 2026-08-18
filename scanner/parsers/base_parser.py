from abc import ABC, abstractmethod
from typing import List
from models.network import NetworkModel

class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw_output: str) -> List[NetworkModel]:
        pass

    @staticmethod
    def calculate_percent(dbm: int) -> int:
        if dbm <= -100:
            return 0
        elif dbm >= -30:
            return 100
        return int(2 * (dbm + 100))
