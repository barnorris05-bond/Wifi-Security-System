import sys
from scanner.parsers.windows_parser import WindowsNetshParser
from scanner.scanner_factory import ScannerFactory

def test_windows_netsh_parser():
    sample_output = '''
SSID 1 : Office_Network
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 85%
         Radio type         : 802.11ax
         Channel            : 36
'''
    parser = WindowsNetshParser()
    nets = parser.parse(sample_output)
    assert len(nets) == 1
    assert nets[0].ssid == "Office_Network"
    assert nets[0].bssid == "00:11:22:33:44:55"
    assert nets[0].encryption == "WPA2"
    assert nets[0].channel == 36

def test_scanner_factory_platform():
    scanner = ScannerFactory.get_scanner("Wi-Fi")
    if sys.platform == "win32":
        assert scanner.__class__.__name__ == "WindowsWLANScanner"
