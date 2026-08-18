import re
from typing import List
from models.network import NetworkModel
from scanner.parsers.base_parser import BaseParser

class NMCLIParser(BaseParser):
    @staticmethod
    def _split_escaped(text: str, delimiter: str = ':') -> List[str]:
        tokens, current, i = [], [], 0
        while i < len(text):
            if text[i] == '\\' and i + 1 < len(text):
                current.append(text[i + 1])
                i += 2
            elif text[i] == delimiter:
                tokens.append(''.join(current))
                current = []
                i += 1
            else:
                current.append(text[i])
                i += 1
        tokens.append(''.join(current))
        return tokens

    def parse(self, raw_output: str) -> List[NetworkModel]:
        networks = []
        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            parts = self._split_escaped(line, ':')
            if len(parts) < 6:
                continue

            bssid = parts[0].strip().upper()
            ssid = parts[1].strip() or "<Hidden SSID>"
            try:
                channel = int(parts[2].strip())
            except ValueError:
                channel = 0

            freq_match = re.search(r'(\d+)', parts[3].strip())
            freq_mhz = float(freq_match.group(1)) if freq_match else 0.0

            if 2400 <= freq_mhz <= 2500:
                band = "2.4 GHz"
            elif 4900 <= freq_mhz <= 5899:
                band = "5 GHz"
            elif freq_mhz >= 5900:
                band = "6 GHz"
            else:
                band = "Unknown"

            try:
                signal_percent = int(parts[4].strip())
            except ValueError:
                signal_percent = 0

            signal_dbm = int((signal_percent / 2) - 100)
            sec_raw = parts[5].strip().upper()

            encryption = "OPEN"
            authentication = "NONE"

            if "WPA3" in sec_raw:
                encryption = "WPA3"
            elif "WPA2" in sec_raw or "RSN" in sec_raw:
                encryption = "WPA2"
            elif "WPA" in sec_raw:
                encryption = "WPA"
            elif "WEP" in sec_raw:
                encryption = "WEP"

            if "802.1X" in sec_raw or "EAP" in sec_raw:
                authentication = "ENTERPRISE"
            elif encryption != "OPEN":
                authentication = "PERSONAL"

            networks.append(NetworkModel(
                ssid=ssid, bssid=bssid, channel=channel, frequency_mhz=freq_mhz,
                band=band, signal_dbm=signal_dbm, signal_percent=signal_percent,
                encryption=encryption, authentication=authentication
            ))
        return networks
