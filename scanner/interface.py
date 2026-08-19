import os
import re
import subprocess
import sys
from typing import List, Optional

HIDDEN_SSID = "<Hidden SSID>"


class InterfaceManager:
    @staticmethod
    def get_wifi_interfaces() -> List[str]:
        """Return a list of detectable Wi-Fi interfaces on the current platform."""
        if sys.platform == "win32":
            return InterfaceManager._windows_interfaces()

        linux_interfaces = InterfaceManager._linux_interfaces()
        if linux_interfaces:
            return linux_interfaces

        fallback = ["wlan0", "wlan1", "wifi0", "wlp2s0"]
        return [iface for iface in fallback if InterfaceManager._interface_exists(iface)]

    @staticmethod
    def _windows_interfaces() -> List[str]:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                check=False,
            )
            output = result.stdout or ""
            names = []
            for line in output.splitlines():
                match = re.search(r"^\s*There is\s+1\s+interface\s+on\s+the\s+system:\s*", line, re.IGNORECASE)
                if match:
                    continue
                match = re.search(r"^\s*Name\s*:\s*(.+)$", line, re.IGNORECASE)
                if match:
                    iface = match.group(1).strip()
                    if iface:
                        names.append(iface)
            return names or ["Wi-Fi"]
        except OSError:
            return ["Wi-Fi"]

    @staticmethod
    def _linux_interfaces() -> List[str]:
        if os.path.isdir("/sys/class/net"):
            interfaces = []
            for name in sorted(os.listdir("/sys/class/net")):
                path = os.path.join("/sys/class/net", name)
                if not os.path.isdir(path):
                    continue
                if os.path.exists(os.path.join(path, "wireless")):
                    interfaces.append(name)
                elif name.startswith(("wlan", "wifi", "wlp")):
                    interfaces.append(name)
            if interfaces:
                return interfaces

        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                matches = re.findall(r"^\s*Interface\s+(\S+)", result.stdout, flags=re.MULTILINE)
                if matches:
                    return matches
        except OSError:
            pass

        return []

    @staticmethod
    def _interface_exists(name: str) -> bool:
        return os.path.exists(os.path.join("/sys/class/net", name)) or (sys.platform == "win32")

    @staticmethod
    def get_default_interface() -> Optional[str]:
        interfaces = InterfaceManager.get_wifi_interfaces()
        return interfaces[0] if interfaces else None