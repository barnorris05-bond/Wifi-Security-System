import re
from typing import List

from models.network import NetworkModel
from scanner.parsers.base_parser import BaseParser, HIDDEN_SSID


class IWListParser(BaseParser):
    def parse(self, raw_output: str) -> List[NetworkModel]:
        networks = []
        cell_blocks = re.split(r'\n(?=\s*Cell\s+\d+)', raw_output)

        for block in cell_blocks:
            bssid_match = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', block)
            if not bssid_match:
                continue

            bssid = bssid_match.group(1).upper()

            ssid_match = re.search(r'ESSID:"([^"]*)"', block)
            ssid = ssid_match.group(1) if ssid_match and ssid_match.group(1) else HIDDEN_SSID

            freq_match = re.search(r'Frequency:([\d.]+)\s*GHz', block)
            freq_mhz = float(freq_match.group(1)) * 1000.0 if freq_match else 0.0

            if 2400 <= freq_mhz <= 2500:
                band = "2.4 GHz"
            elif 4900 <= freq_mhz <= 5899:
                band = "5 GHz"
            elif freq_mhz >= 5900:
                band = "6 GHz"
            else:
                band = "Unknown"

            chan_match = re.search(r'Channel:(\d+)', block)
            channel = int(chan_match.group(1)) if chan_match else 0

            signal_match = re.search(r'Signal level=(-\d+|\d+/\d+)', block)
            if signal_match:
                sig_str = signal_match.group(1)
                if '/' in sig_str:
                    num, den = map(int, sig_str.split('/'))
                    signal_percent = int((num / den) * 100)
                    signal_dbm = int((signal_percent / 2) - 100)
                else:
                    signal_dbm = int(sig_str)
                    signal_percent = self.calculate_percent(signal_dbm)
            else:
                signal_dbm = None
                signal_percent = 0

            text_upper = block.upper()
            if 'IEEE 802.11I/WPA2' in text_upper or 'WPA2' in text_upper:
                encryption = 'WPA2'
            elif 'WPA3' in text_upper:
                encryption = 'WPA3'
            elif 'WPA' in text_upper:
                encryption = 'WPA'
            elif 'ENCRYPTION KEY:ON' in text_upper:
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
