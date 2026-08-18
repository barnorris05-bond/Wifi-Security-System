from models.network import NetworkModel
from analyzer.security import SecurityAnalyzer
from scanner.parsers.nmcli_parser import NMCLIParser

def test_security_analyzer_open():
    net = NetworkModel(ssid="Public", bssid="11:22:33:44:55:66", channel=1, frequency_mhz=2412, band="2.4 GHz", encryption="OPEN", authentication="NONE")
    assessment = SecurityAnalyzer.analyze(net)
    assert assessment.risk_score == 70
    assert assessment.risk_level == "CRITICAL"

def test_nmcli_parser_escaped_colon():
    raw_sample = "AA\\:BB\\:CC\\:DD\\:EE\\:FF:Open_Cafe:11:2462 MHz:85:WPA3"
    parser = NMCLIParser()
    networks = parser.parse(raw_sample)
    assert len(networks) == 1
    assert networks[0].bssid == "AA:BB:CC:DD:EE:FF"
    assert networks[0].ssid == "Open_Cafe"
    assert networks[0].encryption == "WPA3"
