from analyzer.frequency import FrequencyResolver
from analyzer.history import HistoricalAnalyzer

def test_frequency_resolution():
    assert FrequencyResolver.resolve_from_frequency(2412) == "2.4 GHz"
    assert FrequencyResolver.resolve_from_frequency(5180) == "5 GHz"
    assert FrequencyResolver.resolve_from_frequency(6135) == "6 GHz"

def test_channel_resolution():
    info_24 = FrequencyResolver.resolve_from_channel(6)
    assert info_24.band == "2.4 GHz"
    assert info_24.frequency_mhz == 2437.0

    info_5 = FrequencyResolver.resolve_from_channel(36)
    assert info_5.band == "5 GHz"
    assert info_5.frequency_mhz == 5180.0

    info_6 = FrequencyResolver.resolve_from_channel(33)
    assert info_6.band == "6 GHz"

def test_historical_scan_comparison():
    prev = [{"bssid": "11:22:33:44:55:66", "ssid": "Test", "encryption": "WPA2", "channel": 6}]
    curr = [{"bssid": "11:22:33:44:55:66", "ssid": "Test", "encryption": "WPA3", "channel": 6}]
    
    changes = HistoricalAnalyzer.compare_scans(prev, curr)
    assert len(changes) == 1
    assert changes[0].change_type == "SECURITY_CHANGED"
