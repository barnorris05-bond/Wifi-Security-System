import re
from typing import List

from models.network import NetworkModel
from scanner.parsers.base_parser import BaseParser, HIDDEN_SSID


class IWParser(BaseParser):
    def parse(self, raw_output: str) -> List[NetworkModel]:
        networks = []
        bss_blocks = re.split(r'\n(?=BSS\s+)', raw_output)

        for block in bss_blocks:
            bssid_match = re.search(r'BSS\s+([0-9a-fa-f:]{17})', block, re.IGNORECASE)
            if not bssid_match:
                continue

            bssid = bssid_match.group(1).upper()
            ssid_match = re.search(r'SSID:\s*(.*)', block)
            ssid = ssid_match.group(1).strip() if ssid_match and ssid_match.group(1).strip() else HIDDEN_SSID

            freq_match = re.search(r'freq:\s*([\d.]+)', block)
            freq_mhz = float(freq_match.group(1)) if freq_match else 0.0

            if 2400 <= freq_mhz <= 2500:
                band = "2.4 GHz"
            elif 4900 <= freq_mhz <= 5899:
                band = "5 GHz"
            elif freq_mhz >= 5900:
                band = "6 GHz"
            else:
                band = "Unknown"

            signal_match = re.search(r'signal:\s*(-\d+[\.\d]*)', block)
            signal_dbm = int(float(signal_match.group(1))) if signal_match else None
            signal_percent = self.calculate_percent(signal_dbm) if signal_dbm is not None else 0

            chan_match = re.search(r'DS Parameter set: channel (\d+)', block)
            if chan_match:
                channel = int(chan_match.group(1))
            elif 2412 <= freq_mhz <= 2484:
                channel = int((freq_mhz - 2407) / 5)
            else:
                channel = 0

            text_upper = block.upper()
            if 'WPA3' in text_upper or 'SAE' in text_upper:
                encryption = 'WPA3'
            elif 'RSN' in text_upper or 'WPA2' in text_upper:
                encryption = 'WPA2'
            elif 'WPA' in text_upper:
                encryption = 'WPA'
            elif 'WEP' in text_upper or 'PRIVACY' in text_upper:
                encryption = 'WEP'
            else:
                encryption = 'OPEN'

            if '802.1X' in text_upper or 'EAP' in text_upper:
                authentication = 'ENTERPRISE'
            elif encryption != 'OPEN':
                authentication = 'PERSONAL'
            else:
                authentication = 'NONE'

            networks.append(NetworkModel(
                ssid=ssid, bssid=bssid, channel=channel, frequency_mhz=freq_mhz,
                band=band, signal_dbm=signal_dbm, signal_percent=signal_percent,
                encryption=encryption, authentication=authentication
            ))
        return networks
