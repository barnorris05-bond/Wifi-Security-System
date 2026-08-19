import json

def generate_json_report(scan_session) -> str:
    return json.dumps(scan_session.to_dict(), indent=2)
