import re
from typing import List
from models.network import NetworkModel
from scanner.parsers.base_parser import BaseParser

class WindowsNetshParser(BaseParser):
    def parse(self, raw_output: str) -> List[NetworkModel]:
        networks = []
        ssid_blocks = re.split(r'\n(?=SSID\s+\d+\s+:)', raw_output)

        for block in ssid_blocks:
            ssid_match = re.search(r'SSID\s+\d+\s+:\s*([^\r\n]*)', block)
            if not ssid_match:
                continue

            raw_ssid = ssid_match.group(1).strip()
            if not raw_ssid or "Network type" in raw_ssid:
                ssid = "<Hidden SSID>"
            else:
                ssid = raw_ssid

            auth_match = re.search(r'Authentication\s+:\s*([^\r\n]*)', block)
            enc_match = re.search(r'Encryption\s+:\s*([^\r\n]*)', block)

            raw_auth = auth_match.group(1).strip().upper() if auth_match else "UNKNOWN"
            raw_enc = enc_match.group(1).strip().upper() if enc_match else "UNKNOWN"

            bssid_blocks = re.split(r'\n(?=\s*BSSID\s+\d+\s+:)', block)
            for b_block in bssid_blocks[1:]:
                bssid_match = re.search(r'BSSID\s+\d+\s+:\s*([0-9a-fa-f:]{17})', b_block, re.IGNORECASE)
                if not bssid_match:
                    continue
                bssid = bssid_match.group(1).upper()

                sig_match = re.search(r'Signal\s+:\s*(\d+)%', b_block)
                signal_percent = int(sig_match.group(1)) if sig_match else 0
                signal_dbm = int((signal_percent / 2) - 100)

                chan_match = re.search(r'Channel\s+:\s*(\d+)', b_block)
                channel = int(chan_match.group(1)) if chan_match else 0

                if 1 <= channel <= 14:
                    freq_mhz = 2407.0 + (channel * 5.0) if channel != 14 else 2484.0
                    band = "2.4 GHz"
                elif 36 <= channel <= 177:
                    freq_mhz = 5000.0 + (channel * 5.0)
                    band = "5 GHz"
                else:
                    freq_mhz = 0.0
                    band = "Unknown"

                encryption = "OPEN"
                authentication = "NONE"

                if "WPA3" in raw_auth or "WPA3" in raw_enc:
                    encryption = "WPA3"
                elif "WPA2" in raw_auth or "WPA2" in raw_enc:
                    encryption = "WPA2"
                elif "WPA" in raw_auth or "WPA" in raw_enc:
                    encryption = "WPA"
                elif "WEP" in raw_enc:
                    encryption = "WEP"

                if "ENTERPRISE" in raw_auth or "802.1X" in raw_auth:
                    authentication = "ENTERPRISE"
                elif encryption != "OPEN":
                    authentication = "PERSONAL"

                networks.append(NetworkModel(
                    ssid=ssid, bssid=bssid, channel=channel, frequency_mhz=freq_mhz,
                    band=band, signal_dbm=signal_dbm, signal_percent=signal_percent,
                    encryption=encryption, authentication=authentication
                ))

        return networks
