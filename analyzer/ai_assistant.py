import os
from openai import OpenAI

class NemotronAnalyzer:
    def __init__(self, mode: str = "local"):
        """
        mode: 'local' (Ollama) or 'cloud' (NVIDIA API)
        """
        self.mode = mode
        
        if self.mode == "cloud":
            api_key = os.getenv("NVIDIA_API_KEY")
            if not api_key:
                raise ValueError("NVIDIA_API_KEY environment variable is missing for cloud mode.")
            self.client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=api_key
            )
            self.model_name = "nvidia/nemotron-4-340b-instruct"
        else:
            # Local Ollama OpenAI-compatible endpoint
            self.client = OpenAI(
                base_url="http://localhost:11434/v1",
                api_key="ollama"  # Required placeholder string for OpenAI client
            )
            self.model_name = "nemotron-3-nano:4b"

    def analyze_network_security(self, ssid: str, security_type: str, signal_dbm: int, channel: int) -> str:
        prompt = f"""
        You are a Wi-Fi Security Expert. Analyze the following access point and give a concise risk summary:
        - SSID: {ssid}
        - Security: {security_type}
        - Signal Strength: {signal_dbm} dBm
        - Channel: {channel}

        Highlight vulnerabilities (e.g., Open/WEP/WPA1), potential Evil Twin risks, or channel interference issues in 3 concise bullet points.
        """

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=300
        )
        return response.choices[0].message.content
